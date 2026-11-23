"""Django: wrap the WSGI application in your project's wsgi.py.

    # mysite/wsgi.py
    import os
    from django.core.wsgi import get_wsgi_application
    from aegis.integrations import protect_wsgi

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mysite.settings")
    application = protect_wsgi(get_wsgi_application(), source_root=os.path.dirname(__file__),
                               mode="block", heal="propose", app_name="mysite")
"""
