import datetime
from functools import update_wrapper, wraps
from unittest import TestCase, mock

from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import (
    login_required,
    permission_required,
    user_passes_test,
)
from django.http import HttpRequest, HttpResponse, HttpResponseNotAllowed
from django.middleware.clickjacking import XFrameOptionsMiddleware
from django.test import SimpleTestCase
from django.utils.decorators import method_decorator
from django.utils.functional import keep_lazy, keep_lazy_text, lazy
from django.utils.safestring import mark_safe
from django.views.decorators.cache import cache_control, cache_page, never_cache
from django.views.decorators.clickjacking import (
    xframe_options_deny,
    xframe_options_exempt,
    xframe_options_sameorigin,
)
from django.views.decorators.common import no_append_slash
from django.views.decorators.csrf import (
    csrf_exempt,
    csrf_protect,
    ensure_csrf_cookie,
    requires_csrf_token,
)
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.decorators.gzip import gzip_page
from django.views.decorators.http import (
    condition,
    conditional_page,
    etag,
    last_modified,
    require_GET,
    require_http_methods,
    require_POST,
    require_safe,
)
from django.views.decorators.vary import vary_on_cookie, vary_on_headers


def fully_decorated(request):
    """Expected __doc__"""
    return HttpResponse("<html><body>dummy</body></html>")


fully_decorated.anything = "Expected __dict__"


def compose(*functions):
    # compose(f, g)(*args, **kwargs) == f(g(*args, **kwargs))
    functions = list(reversed(functions))

    def _inner(*args, **kwargs):
        result = functions[0](*args, **kwargs)
        for f in functions[1:]:
            result = f(result)
        return result

    return _inner


full_decorator = compose(
    # django.views.decorators.http
    require_http_methods(["GET"]),
    require_GET,
    require_POST,
    require_safe,
    condition(lambda r: None, lambda r: None),
    # django.views.decorators.vary
    vary_on_headers("Accept-language"),
    vary_on_cookie,
    # django.views.decorators.cache
    cache_page(60 * 15),
    cache_control(private=True),
    never_cache,
    # django.contrib.auth.decorators
    # Apply user_passes_test twice to check #9474
    user_passes_test(lambda u: True),
    login_required,
    permission_required("change_world"),
    # django.contrib.admin.views.decorators
    staff_member_required,
    # django.utils.functional
    keep_lazy(HttpResponse),
    keep_lazy_text,
    lazy,
    # django.utils.safestring
    mark_safe,
)

fully_decorated = full_decorator(fully_decorated)


class DecoratorsTest(TestCase):
    def test_attributes(self):
        """
        Built-in decorators set certain attributes of the wrapped function.
        """
        self.assertEqual(fully_decorated.__name__, "fully_decorated")
        self.assertEqual(fully_decorated.__doc__, "Expected __doc__")
        self.assertEqual(fully_decorated.__dict__["anything"], "Expected __dict__")

    def test_user_passes_test_composition(self):
        """
        The user_passes_test decorator can be applied multiple times (#9474).
        """

        def test1(user):
            user.decorators_applied.append("test1")
            return True

        def test2(user):
            user.decorators_applied.append("test2")
            return True

        def callback(request):
            return request.user.decorators_applied

        callback = user_passes_test(test1)(callback)
        callback = user_passes_test(test2)(callback)

        class DummyUser:
            pass

        class DummyRequest:
            pass

        request = DummyRequest()
        request.user = DummyUser()
        request.user.decorators_applied = []
        response = callback(request)

        self.assertEqual(response, ["test2", "test1"])

    def test_cache_page(self):
        def my_view(request):
            return "response"

        my_view_cached = cache_page(123)(my_view)
        self.assertEqual(my_view_cached(HttpRequest()), "response")
        my_view_cached2 = cache_page(123, key_prefix="test")(my_view)
        self.assertEqual(my_view_cached2(HttpRequest()), "response")

    def test_require_safe_accepts_only_safe_methods(self):
        """
        Test for the require_safe decorator.
        A view returns either a response or an exception.
        Refs #15637.
        """

        def my_view(request):
            return HttpResponse("OK")

        my_safe_view = require_safe(my_view)
        request = HttpRequest()
        request.method = "GET"
        self.assertIsInstance(my_safe_view(request), HttpResponse)
        request.method = "HEAD"
        self.assertIsInstance(my_safe_view(request), HttpResponse)
        request.method = "POST"
        self.assertIsInstance(my_safe_view(request), HttpResponseNotAllowed)
        request.method = "PUT"
        self.assertIsInstance(my_safe_view(request), HttpResponseNotAllowed)
        request.method = "DELETE"
        self.assertIsInstance(my_safe_view(request), HttpResponseNotAllowed)


# For testing method_decorator, a decorator that assumes a single argument.
# We will get type arguments if there is a mismatch in the number of arguments.
def simple_dec(func):
    @wraps(func)
    def wrapper(arg):
        return func("test:" + arg)

    return wrapper


simple_dec_m = method_decorator(simple_dec)


# For testing method_decorator, two decorators that add an attribute to the function
def myattr_dec(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    wrapper.myattr = True
    return wrapper


myattr_dec_m = method_decorator(myattr_dec)


def myattr2_dec(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    wrapper.myattr2 = True
    return wrapper


myattr2_dec_m = method_decorator(myattr2_dec)


class ClsDec:
    def __init__(self, myattr):
        self.myattr = myattr

    def __call__(self, f):
        def wrapper():
            return f() and self.myattr

        return update_wrapper(wrapper, f)


class MethodDecoratorTests(SimpleTestCase):
    """
    Tests for method_decorator
    """

    def test_preserve_signature(self):
        class Test:
            @simple_dec_m
            def say(self, arg):
                return arg

        self.assertEqual("test:hello", Test().say("hello"))

    def test_preserve_attributes(self):
        # Sanity check myattr_dec and myattr2_dec
        @myattr_dec
        def func():
            pass

        self.assertIs(getattr(func, "myattr", False), True)

        @myattr2_dec
        def func():
            pass

        self.assertIs(getattr(func, "myattr2", False), True)

        @myattr_dec
        @myattr2_dec
        def func():
            pass

        self.assertIs(getattr(func, "myattr", False), True)
        self.assertIs(getattr(func, "myattr2", False), False)

        # Decorate using method_decorator() on the method.
        class TestPlain:
            @myattr_dec_m
            @myattr2_dec_m
            def method(self):
                "A method"
                pass

        # Decorate using method_decorator() on both the class and the method.
        # The decorators applied to the methods are applied before the ones
        # applied to the class.
        @method_decorator(myattr_dec_m, "method")
        class TestMethodAndClass:
            @method_decorator(myattr2_dec_m)
            def method(self):
                "A method"
                pass

        # Decorate using an iterable of function decorators.
        @method_decorator((myattr_dec, myattr2_dec), "method")
        class TestFunctionIterable:
            def method(self):
                "A method"
                pass

        # Decorate using an iterable of method decorators.
        decorators = (myattr_dec_m, myattr2_dec_m)

        @method_decorator(decorators, "method")
        class TestMethodIterable:
            def method(self):
                "A method"
                pass

        tests = (
            TestPlain,
            TestMethodAndClass,
            TestFunctionIterable,
            TestMethodIterable,
        )
        for Test in tests:
            with self.subTest(Test=Test):
                self.assertIs(getattr(Test().method, "myattr", False), True)
                self.assertIs(getattr(Test().method, "myattr2", False), True)
                self.assertIs(getattr(Test.method, "myattr", False), True)
                self.assertIs(getattr(Test.method, "myattr2", False), True)
                self.assertEqual(Test.method.__doc__, "A method")
                self.assertEqual(Test.method.__name__, "method")

    def test_new_attribute(self):
        """A decorator that sets a new attribute on the method."""

        def decorate(func):
            func.x = 1
            return func

        class MyClass:
            @method_decorator(decorate)
            def method(self):
                return True

        obj = MyClass()
        self.assertEqual(obj.method.x, 1)
        self.assertIs(obj.method(), True)

    def test_bad_iterable(self):
        decorators = {myattr_dec_m, myattr2_dec_m}
        msg = "'set' object is not subscriptable"
        with self.assertRaisesMessage(TypeError, msg):

            @method_decorator(decorators, "method")
            class TestIterable:
                def method(self):
                    "A method"
                    pass

    # Test for argumented decorator
    def test_argumented(self):
        class Test:
            @method_decorator(ClsDec(False))
            def method(self):
                return True

        self.assertIs(Test().method(), False)

    def test_descriptors(self):
        def original_dec(wrapped):
            def _wrapped(arg):
                return wrapped(arg)

            return _wrapped

        method_dec = method_decorator(original_dec)

        class bound_wrapper:
            def __init__(self, wrapped):
                self.wrapped = wrapped
                self.__name__ = wrapped.__name__

            def __call__(self, arg):
                return self.wrapped(arg)

            def __get__(self, instance, cls=None):
                return self

        class descriptor_wrapper:
            def __init__(self, wrapped):
                self.wrapped = wrapped
                self.__name__ = wrapped.__name__

            def __get__(self, instance, cls=None):
                return bound_wrapper(self.wrapped.__get__(instance, cls))

        class Test:
            @method_dec
            @descriptor_wrapper
            def method(self, arg):
                return arg

        self.assertEqual(Test().method(1), 1)

    def test_class_decoration(self):
        """
        @method_decorator can be used to decorate a class and its methods.
        """

        def deco(func):
            def _wrapper(*args, **kwargs):
                return True

            return _wrapper

        @method_decorator(deco, name="method")
        class Test:
            def method(self):
                return False

        self.assertTrue(Test().method())

    def test_tuple_of_decorators(self):
        """
        @method_decorator can accept a tuple of decorators.
        """

        def add_question_mark(func):
            def _wrapper(*args, **kwargs):
                return func(*args, **kwargs) + "?"

            return _wrapper

        def add_exclamation_mark(func):
            def _wrapper(*args, **kwargs):
                return func(*args, **kwargs) + "!"

            return _wrapper

        # The order should be consistent with the usual order in which
        # decorators are applied, e.g.
        #    @add_exclamation_mark
        #    @add_question_mark
        #    def func():
        #        ...
        decorators = (add_exclamation_mark, add_question_mark)

        @method_decorator(decorators, name="method")
        class TestFirst:
            def method(self):
                return "hello world"

        class TestSecond:
            @method_decorator(decorators)
            def method(self):
                return "hello world"

        self.assertEqual(TestFirst().method(), "hello world?!")
        self.assertEqual(TestSecond().method(), "hello world?!")

    def test_invalid_non_callable_attribute_decoration(self):
        """
        @method_decorator on a non-callable attribute raises an error.
        """
        msg = (
            "Cannot decorate 'prop' as it isn't a callable attribute of "
            "<class 'Test'> (1)"
        )
        with self.assertRaisesMessage(TypeError, msg):

            @method_decorator(lambda: None, name="prop")
            class Test:
                prop = 1

                @classmethod
                def __module__(cls):
                    return "tests"

    def test_invalid_method_name_to_decorate(self):
        """
        @method_decorator on a nonexistent method raises an error.
        """
        msg = (
            "The keyword argument `name` must be the name of a method of the "
            "decorated class: <class 'Test'>. Got 'nonexistent_method' instead"
        )
        with self.assertRaisesMessage(ValueError, msg):

            @method_decorator(lambda: None, name="nonexistent_method")
            class Test:
                @classmethod
                def __module__(cls):
                    return "tests"

    def test_wrapper_assignments(self):
        """@method_decorator preserves wrapper assignments."""
        func_name = None
        func_module = None

        def decorator(func):
            @wraps(func)
            def inner(*args, **kwargs):
                nonlocal func_name, func_module
                func_name = getattr(func, "__name__", None)
                func_module = getattr(func, "__module__", None)
                return func(*args, **kwargs)

            return inner

        class Test:
            @method_decorator(decorator)
            def method(self):
                return "tests"

        Test().method()
        self.assertEqual(func_name, "method")
        self.assertIsNotNone(func_module)


class SyncAndAsyncDecoratorTests(TestCase):
    """
    Tests to make sure all builtin decorators declare themselves as sync and
    async capable.
    """

    def test_decorators_syanc_and_async_capable(self):
        decorators = (
            cache_page,
            cache_control,
            never_cache,
            xframe_options_deny,
            xframe_options_sameorigin,
            xframe_options_exempt,
            no_append_slash,
            csrf_protect,
            requires_csrf_token,
            ensure_csrf_cookie,
            csrf_exempt,
            gzip_page,
            sensitive_variables,
            sensitive_post_parameters,
            conditional_page,
            require_http_methods,
            require_GET,
            require_POST,
            require_safe,
            condition,
            etag,
            last_modified,
            vary_on_headers,
            vary_on_cookie,
            user_passes_test,
            login_required,
            permission_required,
        )

        for decorator in decorators:
            with self.subTest(decorator):
                self.assertTrue(decorator.sync_capable)
                self.assertTrue(decorator.async_capable)


class CachePageDecoratorTests(SimpleTestCase):
    """
    Tests for the caching decorators.
    """

    def test_cache_page_decorator(self):
        @cache_page(123)
        def a_view(request):
            return "response"

        response = a_view(HttpRequest())
        self.assertEqual(response, "response")

    async def test_cache_page_decorator_with_async_view(self):
        @cache_page(123)
        async def an_async_view(request):
            return "response"

        response = await an_async_view(HttpRequest())
        self.assertEqual(response, "response")

    def test_cache_page_decorator_with_key_prefix(self):
        @cache_page(123, key_prefix="test")
        def a_view(request):
            return "response"

        response = a_view(HttpRequest())
        self.assertEqual(response, "response")

    async def test_cache_page_decorator_with_key_prefix_with_async_view(self):
        @cache_page(123, key_prefix="test")
        async def an_async_view(request):
            return "response"

        response = await an_async_view(HttpRequest())
        self.assertEqual(response, "response")


class XFrameOptionsDecoratorsTests(SimpleTestCase):
    """
    Tests for the X-Frame-Options decorators.
    """

    def test_deny_decorator(self):
        """
        Ensures @xframe_options_deny properly sets the X-Frame-Options header.
        """

        @xframe_options_deny
        def a_view(request):
            return HttpResponse()

        response = a_view(HttpRequest())
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    async def test_deny_decorator_with_async_view(self):
        """
        Ensures @xframe_options_deny properly sets the X-Frame-Options header.
        """

        @xframe_options_deny
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(HttpRequest())
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_sameorigin_decorator(self):
        """
        Ensures @xframe_options_sameorigin properly sets the X-Frame-Options
        header.
        """

        @xframe_options_sameorigin
        def a_view(request):
            return HttpResponse()

        response = a_view(HttpRequest())
        self.assertEqual(response.headers["X-Frame-Options"], "SAMEORIGIN")

    async def test_sameorigin_decorator_with_async_view(self):
        """
        Ensures @xframe_options_sameorigin properly sets the X-Frame-Options
        header.
        """

        @xframe_options_sameorigin
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(HttpRequest())
        self.assertEqual(response.headers["X-Frame-Options"], "SAMEORIGIN")

    def test_exempt_decorator(self):
        """
        Ensures @xframe_options_exempt properly instructs the
        XFrameOptionsMiddleware to NOT set the header.
        """

        @xframe_options_exempt
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        response = a_view(request)
        self.assertIsNone(response.get("X-Frame-Options"))
        self.assertTrue(response.xframe_options_exempt)

        # Since the real purpose of the exempt decorator is to suppress
        # the middleware's functionality, let's make sure it actually works...
        middleware_response = XFrameOptionsMiddleware(a_view)(request)
        self.assertIsNone(middleware_response.get("X-Frame-Options"))

    async def test_exempt_decorator_with_async_view(self):
        """
        Ensures @xframe_options_exempt properly instructs the
        XFrameOptionsMiddleware to NOT set the header.
        """

        @xframe_options_exempt
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        response = await an_async_view(request)
        self.assertIsNone(response.get("X-Frame-Options"))
        self.assertTrue(response.xframe_options_exempt)

        # Since the real purpose of the exempt decorator is to suppress
        # the middleware's functionality, let's make sure it actually works...
        middleware_response = await XFrameOptionsMiddleware(an_async_view)(request)
        self.assertIsNone(middleware_response.get("X-Frame-Options"))


class HttpRequestProxy:
    def __init__(self, request):
        self._request = request

    def __getattr__(self, attr):
        """Proxy to the underlying HttpRequest object."""
        return getattr(self._request, attr)


class NeverCacheDecoratorTest(SimpleTestCase):
    @mock.patch("time.time")
    def test_never_cache_decorator_headers(self, mocked_time):
        @never_cache
        def a_view(request):
            return HttpResponse()

        mocked_time.return_value = 1167616461.0
        response = a_view(HttpRequest())
        self.assertEqual(
            response.headers["Expires"],
            "Mon, 01 Jan 2007 01:54:21 GMT",
        )
        self.assertEqual(
            response.headers["Cache-Control"],
            "max-age=0, no-cache, no-store, must-revalidate, private",
        )

    @mock.patch("time.time")
    async def test_never_cache_decorator_headers_with_async_view(self, mocked_time):
        @never_cache
        async def an_async_view(request):
            return HttpResponse()

        mocked_time.return_value = 1167616461.0
        response = await an_async_view(HttpRequest())
        self.assertEqual(
            response.headers["Expires"],
            "Mon, 01 Jan 2007 01:54:21 GMT",
        )
        self.assertEqual(
            response.headers["Cache-Control"],
            "max-age=0, no-cache, no-store, must-revalidate, private",
        )

    def test_never_cache_decorator_expires_not_overridden(self):
        @never_cache
        def a_view(request):
            return HttpResponse(headers={"Expires": "tomorrow"})

        response = a_view(HttpRequest())
        self.assertEqual(response.headers["Expires"], "tomorrow")

    async def test_never_cache_decorator_expires_not_overridden_with_async_view(self):
        @never_cache
        async def an_async_view(request):
            return HttpResponse(headers={"Expires": "tomorrow"})

        response = await an_async_view(HttpRequest())
        self.assertEqual(response.headers["Expires"], "tomorrow")

    def test_never_cache_decorator_http_request(self):
        class MyClass:
            @never_cache
            def a_view(self, request):
                return HttpResponse()

        request = HttpRequest()
        msg = (
            "never_cache didn't receive an HttpRequest. If you are decorating "
            "a classmethod, be sure to use @method_decorator."
        )
        with self.assertRaisesMessage(TypeError, msg):
            MyClass().a_view(request)
        with self.assertRaisesMessage(TypeError, msg):
            MyClass().a_view(HttpRequestProxy(request))

    def test_never_cache_decorator_http_request_proxy(self):
        class MyClass:
            @method_decorator(never_cache)
            def a_view(self, request):
                return HttpResponse()

        request = HttpRequest()
        response = MyClass().a_view(HttpRequestProxy(request))
        self.assertIn("Cache-Control", response.headers)
        self.assertIn("Expires", response.headers)


class CacheControlDecoratorTest(SimpleTestCase):
    """
    Tests for the cache control decorator.
    """

    def test_cache_control_decorator_http_request(self):
        class MyClass:
            @cache_control(a="b")
            def a_view(self, request):
                return HttpResponse()

        msg = (
            "cache_control didn't receive an HttpRequest. If you are "
            "decorating a classmethod, be sure to use @method_decorator."
        )
        request = HttpRequest()
        with self.assertRaisesMessage(TypeError, msg):
            MyClass().a_view(request)
        with self.assertRaisesMessage(TypeError, msg):
            MyClass().a_view(HttpRequestProxy(request))

    def test_cache_control_decorator_http_request_proxy(self):
        class MyClass:
            @method_decorator(cache_control(a="b"))
            def a_view(self, request):
                return HttpResponse()

        request = HttpRequest()
        response = MyClass().a_view(HttpRequestProxy(request))
        self.assertEqual(response.headers["Cache-Control"], "a=b")

    def test_cache_control_empty_decorator(self):
        @cache_control()
        def a_view(request):
            return HttpResponse()

        response = a_view(HttpRequest())
        self.assertEqual(response.get("Cache-Control"), "")

    async def test_cache_control_empty_decorator_with_async_view(self):
        @cache_control()
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(HttpRequest())
        self.assertEqual(response.get("Cache-Control"), "")

    def test_cache_control_full_decorator(self):
        @cache_control(max_age=123, private=True, public=True, custom=456)
        def a_view(request):
            return HttpResponse()

        response = a_view(HttpRequest())
        cache_control_items = response.get("Cache-Control").split(", ")
        self.assertEqual(
            set(cache_control_items), {"max-age=123", "private", "public", "custom=456"}
        )

    async def test_cache_control_full_decorator_with_async_view(self):
        @cache_control(max_age=123, private=True, public=True, custom=456)
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(HttpRequest())
        cache_control_items = response.get("Cache-Control").split(", ")
        self.assertEqual(
            set(cache_control_items), {"max-age=123", "private", "public", "custom=456"}
        )


class VaryDecoratorsTests(SimpleTestCase):
    """
    Tests for the vary decorators.
    """

    def test_vary_on_headers_decorator(self):
        @vary_on_headers("Header", "Another-header")
        def a_view(request):
            return HttpResponse()

        response = a_view(HttpRequest())
        self.assertEqual(response.status_code, 200)
        # Assert each decorator argument is in the response header
        vary_items_set = {item.strip() for item in response.get("Vary").split(",")}
        self.assertIn("Header", vary_items_set)
        self.assertIn("Another-header", vary_items_set)

    async def test_vary_on_headers_decorator_with_async_view(self):
        @vary_on_headers("Header", "Another-header")
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(HttpRequest())
        self.assertEqual(response.status_code, 200)
        # Assert each decorator argument is in the response header
        vary_items_set = {item.strip() for item in response.get("Vary").split(",")}
        self.assertIn("Header", vary_items_set)
        self.assertIn("Another-header", vary_items_set)

    def test_vary_on_cookie_decorator(self):
        @vary_on_cookie
        def a_view(request):
            return HttpResponse()

        response = a_view(HttpRequest())
        self.assertEqual(response.status_code, 200)
        vary_items_set = {item.strip() for item in response.get("Vary").split(",")}
        self.assertIn("Cookie", vary_items_set)

    async def test_vary_on_cookie_decorator_with_async_view(self):
        @vary_on_cookie
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(HttpRequest())
        self.assertEqual(response.status_code, 200)
        self.assertIn("Cookie", response.get("Vary"))
        vary_items_set = {item.strip() for item in response.get("Vary").split(",")}
        self.assertIn("Cookie", vary_items_set)


class CommonDecoratorTest(SimpleTestCase):
    """
    Tests for the common decorators.
    """

    def test_no_append_slash_decorator(self):
        @no_append_slash
        def a_view(request):
            return HttpResponse()

        self.assertIs(a_view.should_append_slash, False)
        a_view(HttpRequest())

    async def test_no_append_slash_decorator_with_async_view(self):
        @no_append_slash
        async def an_async_view(request):
            return HttpResponse()

        self.assertIs(an_async_view.should_append_slash, False)
        await an_async_view(HttpRequest())


class CsrfDecoratorTests(SimpleTestCase):
    """
    Tests for the CSRF decorators.
    """

    csrf_token = "1bcdefghij2bcdefghij3bcdefghij4bcdefghij5bcdefghij6bcdefghijABCD"

    def setUp(self):
        # Use request that will trigger the middleware but has a csrf token
        self.request = HttpRequest()
        self.request.method = "POST"
        self.request.POST["csrfmiddlewaretoken"] = self.csrf_token
        self.request.COOKIES["csrftoken"] = self.csrf_token

    def test_csrf_protect_decorator(self):
        @csrf_protect
        def a_view(request):
            return HttpResponse()

        response = a_view(self.request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.request.csrf_processing_done)

    async def test_csrf_protect_decorator_with_async_view(self):
        @csrf_protect
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(self.request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.request.csrf_processing_done)

    def test_requires_csrf_token_decorator(self):
        @requires_csrf_token
        def a_view(request):
            return HttpResponse()

        response = a_view(self.request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.request.csrf_processing_done)

    async def test_requires_csrf_token_decorator_with_async_view(self):
        @requires_csrf_token
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(self.request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.request.csrf_processing_done)

    def test_ensure_csrf_cookie_decorator(self):
        @ensure_csrf_cookie
        def a_view(request):
            return HttpResponse()

        response = a_view(self.request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.request.csrf_processing_done)

    async def test_ensure_csrf_cookie_decorator_with_async_view(self):
        @ensure_csrf_cookie
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(self.request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.request.csrf_processing_done)

    def test_csrf_exempt_decorator(self):
        @csrf_exempt
        def a_view(request):
            return HttpResponse()

        self.assertIs(a_view.csrf_exempt, True)
        a_view(HttpRequest())

    async def test_csrf_exempt_decorator_with_async_view(self):
        @csrf_exempt
        async def an_async_view(request):
            return HttpResponse()

        self.assertIs(an_async_view.csrf_exempt, True)
        await an_async_view(HttpRequest())


class DebugDecoratorsTests(SimpleTestCase):
    """
    Tests for the debug decorators.
    """

    def test_sensitive_variables_without_parameters(self):
        @sensitive_variables()
        def a_view(request):
            return HttpResponse()

        response = a_view(HttpRequest())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(a_view.sensitive_variables, "__ALL__")

    async def test_sensitive_variables_without_parameters_with_async_view(self):
        @sensitive_variables()
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(HttpRequest())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(an_async_view.sensitive_variables, "__ALL__")

    def test_sensitive_variables_with_parameters(self):
        @sensitive_variables("a", "b")
        def a_view(request):
            return HttpResponse()

        response = a_view(HttpRequest())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(a_view.sensitive_variables, ("a", "b"))

    async def test_sensitive_variables_with_parameters_with_async_view(self):
        @sensitive_variables("a", "b")
        async def an_async_view(request):
            return HttpResponse()

        response = await an_async_view(HttpRequest())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(an_async_view.sensitive_variables, ("a", "b"))

    def test_sensitive_post_parameters_without_parameters(self):
        @sensitive_post_parameters()
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        response = a_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(request.sensitive_post_parameters, "__ALL__")

    async def test_sensitive_post_parameters_without_parameters_with_async_view(self):
        @sensitive_post_parameters()
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(request.sensitive_post_parameters, "__ALL__")

    def test_sensitive_post_parameters_with_parameters(self):
        @sensitive_post_parameters("a", "b")
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        response = a_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(request.sensitive_post_parameters, ("a", "b"))

    async def test_sensitive_post_parameters_with_parameters_with_async_view(self):
        @sensitive_post_parameters("a", "b")
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(request.sensitive_post_parameters, ("a", "b"))


class GzipDecoratorsTests(SimpleTestCase):
    """
    Tests for the gzip decorator.
    """

    # Gzip ignores content that is too short
    content = "Content " * 100

    def test_gzip_decorator(self):
        @gzip_page
        def a_view(request):
            return HttpResponse(content=self.content)

        request = HttpRequest()
        request.META["HTTP_ACCEPT_ENCODING"] = "gzip"
        response = a_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get("Content-Encoding"), "gzip")

    async def test_gzip_decorator_with_async_view(self):
        @gzip_page
        async def an_async_view(request):
            return HttpResponse(content=self.content)

        request = HttpRequest()
        request.META["HTTP_ACCEPT_ENCODING"] = "gzip"
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get("Content-Encoding"), "gzip")


class ConditionalTests(SimpleTestCase):
    def test_conditional_page_decorator_successful(self):
        @conditional_page
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "HEAD"
        response = a_view(request)
        self.assertEqual(response.status_code, 200)

    async def test_conditional_page_decorator_successful_with_async_view(self):
        @conditional_page
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "HEAD"
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 200)


class RequireHttpMethodsDecoratorTests(SimpleTestCase):
    def test_require_http_methods_decorator_successful(self):
        @require_http_methods(["HEAD"])
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "HEAD"
        response = a_view(request)
        self.assertEqual(response.status_code, 200)

    async def test_require_http_methods_decorator_successful_with_async_view(self):
        @require_http_methods(["HEAD"])
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "HEAD"
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 200)

    def test_require_http_methods_decorator_unsuccessful(self):
        @require_http_methods(["HEAD"])
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = a_view(request)
        self.assertEqual(response.status_code, 405)

    async def test_require_http_methods_decorator_unsuccessful_with_async_view(self):
        @require_http_methods(["HEAD"])
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 405)

    def test_require_get_decorator_successful(self):
        @require_GET
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = a_view(request)
        self.assertEqual(response.status_code, 200)

    async def test_require_get_decorator_successful_with_async_view(self):
        @require_GET
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 200)

    def test_require_get_decorator_unsuccessful(self):
        @require_GET
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "POST"
        response = a_view(request)
        self.assertEqual(response.status_code, 405)

    async def test_require_get_decorator_unsuccessful_with_async_view(self):
        @require_GET
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "POST"
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 405)

    def test_require_post_decorator_successful(self):
        @require_POST
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "POST"
        response = a_view(request)
        self.assertEqual(response.status_code, 200)

    async def test_require_post_decorator_successful_with_async_view(self):
        @require_POST
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "POST"
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 200)

    def test_require_post_decorator_unsuccessful(self):
        @require_POST
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = a_view(request)
        self.assertEqual(response.status_code, 405)

    async def test_require_post_decorator_unsuccessful_with_async_view(self):
        @require_POST
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 405)

    def test_require_safe_decorator_successful(self):
        @require_safe
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        # Only GET and HEAD are safe methods
        request.method = "HEAD"
        response = a_view(request)
        self.assertEqual(response.status_code, 200)

    async def test_require_safe_decorator_successful_with_async_view(self):
        @require_safe
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        # Only GET and HEAD are safe methods
        request.method = "HEAD"
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 200)

    def test_require_safe_decorator_unsuccessful(self):
        @require_safe
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        # Only GET and HEAD are safe methods
        request.method = "POST"
        response = a_view(request)
        self.assertEqual(response.status_code, 405)

    async def test_require_safe_decorator_unsuccessful_with_async_view(self):
        @require_safe
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        # Only GET and HEAD are safe methods
        request.method = "POST"
        response = await an_async_view(request)
        self.assertEqual(response.status_code, 405)


class HttpDecoratorTests(SimpleTestCase):
    def _etag_func(request, *args, **kwargs):
        return '"abc123"'

    def _last_modified_func(request, *args, **kwargs):
        return datetime.datetime(2020, 1, 1)

    def test_condition_decorator(self):
        @condition(
            etag_func=self._etag_func,
            last_modified_func=self._last_modified_func,
        )
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = a_view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["ETag"], '"abc123"')
        self.assertEqual(
            response.headers["Last-Modified"],
            "Wed, 01 Jan 2020 00:00:00 GMT",
        )

    async def test_condition_decorator_with_async_view(self):
        @condition(
            etag_func=self._etag_func,
            last_modified_func=self._last_modified_func,
        )
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = await an_async_view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["ETag"], '"abc123"')
        self.assertEqual(
            response.headers["Last-Modified"],
            "Wed, 01 Jan 2020 00:00:00 GMT",
        )

    def test_etag_decorator(self):
        @etag(self._etag_func)
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = a_view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["ETag"], '"abc123"')

    async def test_etag_decorator_with_async_view(self):
        @etag(self._etag_func)
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = await an_async_view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["ETag"], '"abc123"')

    def test_last_modified_decorator(self):
        @last_modified(self._last_modified_func)
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = a_view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["Last-Modified"],
            "Wed, 01 Jan 2020 00:00:00 GMT",
        )

    async def test_last_modified_decorator_with_async_view(self):
        @last_modified(self._last_modified_func)
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.method = "GET"
        response = await an_async_view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["Last-Modified"],
            "Wed, 01 Jan 2020 00:00:00 GMT",
        )


class AuthDecoratorTests(SimpleTestCase):
    class DummyUser:
        pass

    def always_pass(self, user):
        return True

    def always_fail(self, user):
        return False

    def dummy_build_absolute_uri(request):
        """
        This is required to bypass the normal login URL resolver methods, so we can
        easily specify one for the test.
        """
        pass

    def user_has_all_perms(self, perms):
        return True

    def user_has_no_perms(self, perms):
        return False

    def test_user_passes_test_decorator_pass(self):
        @user_passes_test(self.always_pass)
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        response = a_view(request)

        self.assertEqual(response.status_code, 200)

    async def test_user_passes_test_decorator_pass_with_async_view(self):
        @user_passes_test(self.always_pass)
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        response = await an_async_view(request)

        self.assertEqual(response.status_code, 200)

    def test_user_passes_test_decorator_fail(self):
        @user_passes_test(self.always_fail, login_url="/test-login")
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        request.path = "/test-next-page"
        request.build_absolute_uri = self.dummy_build_absolute_uri
        response = a_view(request)

        # Assert we get redirected to the login page
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/test-login?next=/test-next-page")

    async def test_user_passes_test_decorator_fail_with_async_view(self):
        @user_passes_test(self.always_fail, login_url="/test-login")
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        request.path = "/test-next-page"
        request.build_absolute_uri = self.dummy_build_absolute_uri
        response = await an_async_view(request)

        # Assert we get redirected to the login page
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/test-login?next=/test-next-page")

    def test_login_required_decorator_pass(self):
        @login_required
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        request.user.is_authenticated = True
        response = a_view(request)

        self.assertEqual(response.status_code, 200)

    async def test_login_required_decorator_pass_with_async_view(self):
        @login_required
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        request.user.is_authenticated = True
        response = await an_async_view(request)

        self.assertEqual(response.status_code, 200)

    def test_login_required_decorator_fail(self):
        @login_required(login_url="/test-login")
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        request.user.is_authenticated = False
        request.path = "/test-next-page"
        request.build_absolute_uri = self.dummy_build_absolute_uri
        response = a_view(request)

        # Assert we get redirected to the login page
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/test-login?next=/test-next-page")

    async def test_login_required_decorator_fail_with_async_view(self):
        @login_required(login_url="/test-login")
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        request.user.is_authenticated = False
        request.path = "/test-next-page"
        request.build_absolute_uri = self.dummy_build_absolute_uri
        response = await an_async_view(request)

        # Assert we get redirected to the login page
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/test-login?next=/test-next-page")

    def test_permission_required_decorator_pass(self):
        @permission_required("test_perm")
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        request.user.has_perms = self.user_has_all_perms
        response = a_view(request)

        self.assertEqual(response.status_code, 200)

    async def test_permission_required_decorator_pass_with_async_view(self):
        @permission_required("test_perm")
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        request.user.has_perms = self.user_has_all_perms
        response = await an_async_view(request)

        self.assertEqual(response.status_code, 200)

    def test_permission_required_decorator_fail(self):
        @permission_required("test_perm", login_url="/test-login")
        def a_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        request.user.has_perms = self.user_has_no_perms
        request.path = "/test-next-page"
        request.build_absolute_uri = self.dummy_build_absolute_uri
        response = a_view(request)

        # Assert we get redirected to the login page
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/test-login?next=/test-next-page")

    async def test_permission_required_decorator_fail_with_async_view(self):
        @permission_required("test_perm", login_url="/test-login")
        async def an_async_view(request):
            return HttpResponse()

        request = HttpRequest()
        request.user = self.DummyUser()
        request.user.has_perms = self.user_has_no_perms
        request.path = "/test-next-page"
        request.build_absolute_uri = self.dummy_build_absolute_uri
        response = await an_async_view(request)

        # Assert we get redirected to the login page
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/test-login?next=/test-next-page")
