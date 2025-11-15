from django.contrib import admin
from django.urls import path, include
from django.contrib import admin
from core import views as core_views


urlpatterns = [
   

    path('admin/', admin.site.urls),
      path('admin/analytics/', admin.site.admin_view(core_views.admin_analytics_view), name='admin-analytics'),
     
    path('', include('core.urls')),  # include app routes (core app)
]
