"""好友申请、资料、隐私和朋友圈的服务器入口。

聊天信封仍由 ChatServer.on_envelope 转发。这里只处理社交状态。
朋友圈正文存在服务器上，点赞和评论才能对所有好友一致；
这和单聊的端到端加密不是同一层。
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from src.protocol import dumps, error_msg, validate_username
from src.social import (
    THREE_DAYS,
    clean_account_visibility,
    clean_avatar,
    clean_bio,
    clean_comment,
    clean_display_name,
    clean_greeting,
    clean_moment_body,
    clean_moment_image,
    clean_post_visibility,
)

SOCIAL_TYPES = {
    "profile_get",
    "profile_set",
    "privacy_get",
    "privacy_set",
    "friend_request",
    "friend_respond",
    "friend_remove",
    "friend_block",
    "friend_list",
    "user_search",
    "moment_post",
    "moment_delete",
    "moment_like",
    "moment_comment",
    "moment_feed",
    "moment_get",
}


async def handle_social(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> bool:
    typ = msg.get("type")
    if typ not in SOCIAL_TYPES:
        return False
    handler = {
        "profile_get": on_profile_get,
        "profile_set": on_profile_set,
        "privacy_get": on_privacy_get,
        "privacy_set": on_privacy_set,
        "friend_request": on_friend_request,
        "friend_respond": on_friend_respond,
        "friend_remove": on_friend_remove,
        "friend_block": on_friend_block,
        "friend_list": on_friend_list,
        "user_search": on_user_search,
        "moment_post": on_moment_post,
        "moment_delete": on_moment_delete,
        "moment_like": on_moment_like,
        "moment_comment": on_moment_comment,
        "moment_feed": on_moment_feed,
        "moment_get": on_moment_get,
    }[typ]
    await handler(server, ws, username, msg)
    return True


def _card(server: Any, username: str) -> dict[str, Any]:
    profile = server.store.get_profile(username)
    privacy = server.store.get_privacy(username)
    online = username in server.online and privacy["show_online"]
    return {
        "username": username,
        "display_name": profile["display_name"],
        "bio": profile["bio"],
        "avatar": profile["avatar"],
        "online": online,
    }


def friend_state(server: Any, username: str) -> dict[str, Any]:
    friends: list[dict[str, Any]] = []
    incoming: list[dict[str, Any]] = []
    outgoing: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for rel in server.store.relations_of(username):
        item = _card(server, rel["username"])
        item["greeting"] = rel["greeting"]
        status = rel["status"]
        if status == "accepted":
            friends.append(item)
        elif status == "pending" and rel["requested_by"] == rel["username"]:
            incoming.append(item)
        elif status == "pending" and rel["requested_by"] == username:
            outgoing.append(item)
        elif status == "blocked" and rel["requested_by"] == username:
            blocked.append(item)
        elif status == "rejected" and rel["requested_by"] == username:
            rejected.append(item)
    friends.sort(key=lambda item: item["username"])
    rejected.sort(key=lambda item: item["username"])
    return {
        "type": "friend_state",
        "friends": friends,
        "incoming": incoming,
        "outgoing": outgoing,
        "blocked": blocked,
        "rejected": rejected,
    }


async def push_social(server: Any, username: str) -> None:
    sock = server.online.get(username)
    if sock is None:
        return
    state = friend_state(server, username)
    state["type"] = "social_update"
    try:
        await sock.send(dumps(state))
    except Exception:
        pass


def _can_see_moment(server: Any, viewer: str, moment: dict[str, Any], now: float | None = None) -> bool:
    if moment["deleted"]:
        return False
    author = moment["author"]
    if viewer == author:
        return True
    if moment["visibility"] != "friends":
        return False
    if not server.store.are_friends(viewer, author):
        return False
    privacy = server.store.get_privacy(author)
    visibility = privacy["moments_visibility"]
    if visibility == "none":
        return False
    if visibility == "three_days":
        current = time.time() if now is None else now
        if current - float(moment["created"]) > THREE_DAYS:
            return False
    return True


def _public_moment(server: Any, viewer: str, moment: dict[str, Any], *, include_image: bool) -> dict[str, Any]:
    profile = server.store.get_profile(moment["author"])
    likes = server.store.moment_likes(moment["id"])
    comments = []
    for comment in server.store.moment_comments(moment["id"]):
        author_profile = server.store.get_profile(comment["author"])
        comments.append(
            {
                "id": comment["id"],
                "author": comment["author"],
                "display_name": author_profile["display_name"],
                "body": comment["body"],
                "created": comment["created"],
            }
        )
    image = moment["image"] if include_image else ""
    return {
        "id": moment["id"],
        "author": moment["author"],
        "display_name": profile["display_name"],
        "avatar": profile["avatar"],
        "body": moment["body"],
        "has_image": bool(moment["image"]),
        "image": image,
        "visibility": moment["visibility"],
        "created": moment["created"],
        "likes": likes,
        "liked": viewer in likes,
        "comments": comments,
        "mine": viewer == moment["author"],
    }


def _require_visible(server: Any, viewer: str, moment_id: str) -> dict[str, Any]:
    moment = server.store.get_moment_row(moment_id)
    if moment is None or not _can_see_moment(server, viewer, moment):
        raise PermissionError("看不到这条朋友圈")
    return moment


async def _notify_moment(server: Any, author: str) -> None:
    targets = set(server.store.friend_names(author))
    targets.add(author)
    for username in targets:
        sock = server.online.get(username)
        if sock is None:
            continue
        try:
            await sock.send(dumps({"type": "moment_update"}))
        except Exception:
            pass


async def on_profile_get(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    target = msg.get("username") or username
    validate_username(target)
    if not server.store.user_exists(target):
        await ws.send(dumps(error_msg("用户不存在")))
        return
    if target != username and not server.store.are_friends(username, target):
        privacy = server.store.get_privacy(target)
        if not privacy["searchable"]:
            await ws.send(dumps(error_msg("对方不允许被搜索")))
            return
    await ws.send(dumps({"type": "profile", "profile": server.store.get_profile(target)}))


async def on_profile_set(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    try:
        display_name = clean_display_name(msg.get("display_name"), username)
        bio = clean_bio(msg.get("bio"))
        avatar = clean_avatar(msg.get("avatar"))
    except Exception as exc:
        await ws.send(dumps(error_msg(str(exc))))
        return
    profile = server.store.set_profile(username, display_name, bio, avatar)
    await ws.send(dumps({"type": "profile", "profile": profile}))
    await push_social(server, username)
    for friend in server.store.friend_names(username):
        await push_social(server, friend)


async def on_privacy_get(server: Any, ws: Any, username: str, _msg: dict[str, Any]) -> None:
    await ws.send(dumps({"type": "privacy", "privacy": server.store.get_privacy(username)}))


async def on_privacy_set(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    try:
        visibility = clean_account_visibility(msg.get("moments_visibility"))
    except Exception as exc:
        await ws.send(dumps(error_msg(str(exc))))
        return
    privacy = server.store.set_privacy(
        username,
        require_approval=bool(msg.get("require_approval", True)),
        moments_visibility=visibility,
        show_online=bool(msg.get("show_online", True)),
        searchable=bool(msg.get("searchable", True)),
    )
    await ws.send(dumps({"type": "privacy", "privacy": privacy}))
    await server._broadcast_presence()


async def on_friend_list(server: Any, ws: Any, username: str, _msg: dict[str, Any]) -> None:
    await ws.send(dumps(friend_state(server, username)))


async def on_user_search(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    query = str(msg.get("query") or "").strip()
    if len(query) > 20:
        await ws.send(dumps(error_msg("搜索太长")))
        return
    users = []
    for name in server.store.directory_for(username, query)[:30]:
        card = _card(server, name)
        rel = server.store.relation(username, name)
        if rel is None:
            card["relation"] = "none"
        elif rel["status"] == "accepted":
            card["relation"] = "friend"
        elif rel["status"] == "blocked":
            card["relation"] = "blocked" if rel["requested_by"] == username else "unavailable"
        elif rel["requested_by"] == username:
            card["relation"] = "outgoing"
        else:
            card["relation"] = "incoming"
        users.append(card)
    await ws.send(dumps({"type": "user_search", "users": users}))


async def on_friend_request(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    target = str(msg.get("to") or "")
    try:
        validate_username(target)
        greeting = clean_greeting(msg.get("greeting"))
    except Exception as exc:
        await ws.send(dumps(error_msg(str(exc))))
        return
    if target == username:
        await ws.send(dumps(error_msg("不能添加自己")))
        return
    if not server.store.user_exists(target):
        await ws.send(dumps(error_msg("用户不存在")))
        return
    rel = server.store.relation(username, target)
    if rel and rel["status"] == "blocked":
        if rel["requested_by"] == username:
            await ws.send(dumps(error_msg("你已拉黑对方，先取消拉黑")))
        else:
            await ws.send(dumps(error_msg("无法向对方发送好友申请")))
        return
    if rel and rel["status"] == "accepted":
        await ws.send(dumps(error_msg("你们已经是好友")))
        return
    if rel and rel["status"] == "pending" and rel["requested_by"] == username:
        await ws.send(dumps(error_msg("好友申请已发送，等待对方同意")))
        return
    if rel and rel["status"] == "pending" and rel["requested_by"] == target:
        server.store.save_relation(
            username, target, status="accepted", requested_by=target, greeting=rel["greeting"]
        )
    else:
        privacy = server.store.get_privacy(target)
        if not privacy["require_approval"]:
            server.store.save_relation(
                username, target, status="accepted", requested_by=username, greeting=greeting
            )
        else:
            server.store.save_relation(
                username, target, status="pending", requested_by=username, greeting=greeting
            )
    await ws.send(dumps(friend_state(server, username)))
    await push_social(server, target)


async def on_friend_respond(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    target = str(msg.get("username") or "")
    try:
        validate_username(target)
    except Exception as exc:
        await ws.send(dumps(error_msg(str(exc))))
        return
    rel = server.store.relation(username, target)
    if rel is None or rel["status"] != "pending" or rel["requested_by"] != target:
        await ws.send(dumps(error_msg("没有待处理的好友申请")))
        return
    if bool(msg.get("accept")):
        server.store.save_relation(
            username,
            target,
            status="accepted",
            requested_by=rel["requested_by"],
            greeting=rel["greeting"],
        )
    else:
        server.store.save_relation(
            username,
            target,
            status="rejected",
            requested_by=rel["requested_by"],
            greeting=rel["greeting"],
        )
    await ws.send(dumps(friend_state(server, username)))
    await push_social(server, target)


async def on_friend_remove(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    target = str(msg.get("username") or "")
    try:
        validate_username(target)
    except Exception as exc:
        await ws.send(dumps(error_msg(str(exc))))
        return
    rel = server.store.relation(username, target)
    if rel and rel["status"] == "blocked" and rel["requested_by"] != username:
        await ws.send(dumps(error_msg("无法解除对方的拉黑")))
        return
    if rel:
        server.store.delete_relation(username, target)
    await ws.send(dumps(friend_state(server, username)))
    await push_social(server, target)


async def on_friend_block(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    target = str(msg.get("username") or "")
    try:
        validate_username(target)
    except Exception as exc:
        await ws.send(dumps(error_msg(str(exc))))
        return
    server.store.save_relation(
        username, target, status="blocked", requested_by=username, greeting=""
    )
    await ws.send(dumps(friend_state(server, username)))
    await push_social(server, target)


async def on_moment_post(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    try:
        body = clean_moment_body(msg.get("body"))
        image = clean_moment_image(msg.get("image"))
        visibility = clean_post_visibility(msg.get("visibility"))
    except Exception as exc:
        await ws.send(dumps(error_msg(str(exc))))
        return
    if not body and not image:
        await ws.send(dumps(error_msg("朋友圈至少要有文字或图片")))
        return
    moment_id = uuid.uuid4().hex
    server.store.insert_moment(moment_id, username, body, image, visibility)
    moment = server.store.get_moment_row(moment_id)
    assert moment is not None
    await ws.send(
        dumps(
            {
                "type": "moment_ok",
                "moment": _public_moment(server, username, moment, include_image=False),
            }
        )
    )
    await _notify_moment(server, username)


async def on_moment_delete(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    moment_id = str(msg.get("id") or "")
    moment = server.store.get_moment_row(moment_id)
    if moment is None or moment["author"] != username:
        await ws.send(dumps(error_msg("只能删除自己的朋友圈")))
        return
    server.store.mark_moment_deleted(moment_id)
    await ws.send(dumps({"type": "moment_ok", "id": moment_id, "deleted": True}))
    await _notify_moment(server, username)


async def on_moment_like(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    moment_id = str(msg.get("id") or "")
    try:
        moment = _require_visible(server, username, moment_id)
    except PermissionError as exc:
        await ws.send(dumps(error_msg(str(exc))))
        return
    server.store.toggle_like(moment_id, username)
    fresh = server.store.get_moment_row(moment_id)
    assert fresh is not None
    await ws.send(
        dumps(
            {
                "type": "moment_ok",
                "moment": _public_moment(server, username, fresh, include_image=False),
            }
        )
    )
    await _notify_moment(server, moment["author"])


async def on_moment_comment(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    moment_id = str(msg.get("id") or "")
    try:
        moment = _require_visible(server, username, moment_id)
        body = clean_comment(msg.get("body"))
    except Exception as exc:
        await ws.send(dumps(error_msg(str(exc))))
        return
    server.store.add_comment(uuid.uuid4().hex, moment_id, username, body)
    fresh = server.store.get_moment_row(moment_id)
    assert fresh is not None
    await ws.send(
        dumps(
            {
                "type": "moment_ok",
                "moment": _public_moment(server, username, fresh, include_image=False),
            }
        )
    )
    await _notify_moment(server, moment["author"])


async def on_moment_feed(server: Any, ws: Any, username: str, _msg: dict[str, Any]) -> None:
    moments = []
    for moment in server.store.recent_moments(40):
        if not _can_see_moment(server, username, moment):
            continue
        moments.append(_public_moment(server, username, moment, include_image=False))
    await ws.send(dumps({"type": "moment_feed", "moments": moments[:20]}))


async def on_moment_get(server: Any, ws: Any, username: str, msg: dict[str, Any]) -> None:
    moment_id = str(msg.get("id") or "")
    try:
        moment = _require_visible(server, username, moment_id)
    except PermissionError as exc:
        await ws.send(dumps(error_msg(str(exc))))
        return
    await ws.send(
        dumps(
            {
                "type": "moment_item",
                "moment": _public_moment(server, username, moment, include_image=True),
            }
        )
    )
