from django.http import HttpResponseRedirect
from django.urls import reverse

def role_required(*roles):
    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):
            user_role = request.session.get('role')
            if user_role not in roles:
                return HttpResponseRedirect(reverse('home'))  # redirect to home if the user doesn't have the required role
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator