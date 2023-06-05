from django.apps import AppConfig
class FileUploadConfig(AppConfig):
    name = 'file_upload'

class AppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app'
