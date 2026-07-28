import logging

logger = logging.getLogger("file_sentinel.notifier")


def notify(title: str, message: str, timeout: int = 10) -> None:
    try:
        from plyer import notification

        notification.notify(title=title, message=message, app_name="File Sentinel", timeout=timeout)
    except Exception as exc:
        logger.debug("Desktop notification unavailable, falling back to log output: %s", exc)
        logger.info("%s - %s", title, message)
