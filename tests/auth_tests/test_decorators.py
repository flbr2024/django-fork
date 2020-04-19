from django.conf import settings
from django.contrib.auth import models
from django.contrib.auth.decorators import (
    login_required, permission_required, superuser_required,
)
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, Http404
from django.test import TestCase, override_settings
from django.test.client import RequestFactory

from .test_views import AuthViewsTestCase


@override_settings(ROOT_URLCONF='auth_tests.urls')
class LoginRequiredTestCase(AuthViewsTestCase):
    """
    Tests the login_required decorators
    """

    def testCallable(self):
        """
        login_required is assignable to callable objects.
        """
        class CallableView:
            def __call__(self, *args, **kwargs):
                pass
        login_required(CallableView())

    def testView(self):
        """
        login_required is assignable to normal views.
        """
        def normal_view(request):
            pass
        login_required(normal_view)

    def testLoginRequired(self, view_url='/login_required/', login_url=None):
        """
        login_required works on a simple view wrapped in a login_required
        decorator.
        """
        if login_url is None:
            login_url = settings.LOGIN_URL
        response = self.client.get(view_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(login_url, response.url)
        self.login()
        response = self.client.get(view_url)
        self.assertEqual(response.status_code, 200)

    def testLoginRequiredNextUrl(self):
        """
        login_required works on a simple view wrapped in a login_required
        decorator with a login_url set.
        """
        self.testLoginRequired(view_url='/login_required_login_url/', login_url='/somewhere/')


@override_settings(ROOT_URLCONF='auth_tests.urls')
class SuperuserRequiredTestCase(TestCase):
    """
    Tests the login_required decorators
    """

    def setUp(self):
        self.superuser = models.User.objects.create_superuser(
            username='superuser',
            password='password',
            email='superuser@example.com'
        )

        self.user = models.User.objects.create_user(
            username='user',
            password='password',
            email='user@example.com',
        )

        self.factory = RequestFactory()

    def test_callable(self):
        """
        superuser_required is assignable to callable objects.
        """
        class CallableView:
            def __call__(self, *args, **kwargs):
                pass

        superuser_required(CallableView())

    def test_superuser_required(self):
        """
        superuser_required works as expected.
        """

        @superuser_required(login_url=settings.LOGIN_URL)
        def only_superusers(request):
            return HttpResponse('OK')

        request = self.factory.get('/rand')
        request.user = AnonymousUser()
        response = only_superusers(request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual('/accounts/login/?next=/rand', response.url)

        request = self.factory.get('/rand')
        request.user = self.superuser
        response = only_superusers(request)
        self.assertEqual(response.status_code, 200)

        with self.assertRaises(Http404):
            request = self.factory.get('/rand')
            request.user = self.user
            response = only_superusers(request)
            self.assertEqual(response.status_code, 404)


class PermissionsRequiredDecoratorTest(TestCase):
    """
    Tests for the permission_required decorator
    """
    factory = RequestFactory()

    @classmethod
    def setUpTestData(cls):
        cls.user = models.User.objects.create(username='joe', password='qwerty')
        # Add permissions auth.add_customuser and auth.change_customuser
        perms = models.Permission.objects.filter(codename__in=('add_customuser', 'change_customuser'))
        cls.user.user_permissions.add(*perms)

    def test_many_permissions_pass(self):

        @permission_required(['auth_tests.add_customuser', 'auth_tests.change_customuser'])
        def a_view(request):
            return HttpResponse()
        request = self.factory.get('/rand')
        request.user = self.user
        resp = a_view(request)
        self.assertEqual(resp.status_code, 200)

    def test_many_permissions_in_set_pass(self):

        @permission_required({'auth_tests.add_customuser', 'auth_tests.change_customuser'})
        def a_view(request):
            return HttpResponse()
        request = self.factory.get('/rand')
        request.user = self.user
        resp = a_view(request)
        self.assertEqual(resp.status_code, 200)

    def test_single_permission_pass(self):

        @permission_required('auth_tests.add_customuser')
        def a_view(request):
            return HttpResponse()
        request = self.factory.get('/rand')
        request.user = self.user
        resp = a_view(request)
        self.assertEqual(resp.status_code, 200)

    def test_permissioned_denied_redirect(self):

        @permission_required(['auth_tests.add_customuser', 'auth_tests.change_customuser', 'nonexistent-permission'])
        def a_view(request):
            return HttpResponse()
        request = self.factory.get('/rand')
        request.user = self.user
        resp = a_view(request)
        self.assertEqual(resp.status_code, 302)

    def test_permissioned_denied_exception_raised(self):

        @permission_required([
            'auth_tests.add_customuser', 'auth_tests.change_customuser', 'nonexistent-permission'
        ], raise_exception=True)
        def a_view(request):
            return HttpResponse()
        request = self.factory.get('/rand')
        request.user = self.user
        with self.assertRaises(PermissionDenied):
            a_view(request)
