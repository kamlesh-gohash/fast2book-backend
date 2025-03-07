from app.v1.services.video.video_manager import VideoManager


def get_video_manager() -> VideoManager:
    return VideoManager()
