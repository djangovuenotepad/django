from channels.routing import ProtocolTypeRouter,URLRouter
from django.urls import path
from app import consumers

application = ProtocolTypeRouter({
        'websocket':URLRouter([
                    # websocket相关的路由
                            path('domain_name/ssl_cert/create',consumers.ChatConsumer.as_asgi())
                                ])
        })
