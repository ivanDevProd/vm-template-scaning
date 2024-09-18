"""
URL configuration for image_scanner_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from scanIt import views as scanIt_views
from django.contrib.auth import views as auth_views
from vmTemplateEachProcess import views as vmTemplateEachProcess_views
from django.conf.urls.static import static
from django.conf import settings


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', scanIt_views.url_input_view, name='scanIt'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('vmTemplateEachProcess/<str:process_id>/', vmTemplateEachProcess_views.process_details, name='vmTemplateEachProcess'),
    path('help/', scanIt_views.help_page, name='help_page'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

