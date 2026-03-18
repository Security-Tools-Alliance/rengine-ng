"""
Tests for per-tab project context: X-Project-Slug header and SlugMiddleware.

Pages without a project slug in the URL still receive request.current_project from
the header when the user is allowed; otherwise the first linked project is used.
set_current_project no longer sets the currentProjectId cookie.

Audit note: global dashboard routes use X-Project-Slug (fetch/ajax), GET ?project=,
or the first linked project; slug-scoped routes use the path slug only.
"""

import uuid

from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory
from django.urls import resolve, reverse
from django.utils import timezone
from rolepermissions.roles import assign_role

from dashboard.constants import PROJECT_CONTEXT_QUERY_PARAM
from dashboard.middleware import X_PROJECT_SLUG_HEADER, SlugMiddleware
from dashboard.models import Project
from utils.test_base import BaseTestCase


def _add_session(request):
    middleware = SessionMiddleware(lambda r: None)
    middleware.process_request(request)
    request.session.save()


class SlugMiddlewareHeaderTestCase(BaseTestCase):
    """SlugMiddleware resolves project from X-Project-Slug when URL has no slug."""

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()

    def test_x_project_slug_sets_current_project_when_allowed(self):
        uid = uuid.uuid4().hex[:8]
        p2 = Project.objects.create(
            slug=f"header-proj-{uid}",
            name=f"Header Project {uid}",
            insert_date=timezone.now(),
        )
        p2.users.add(self.user)

        request = self.factory.get("/profile/")
        request.META[X_PROJECT_SLUG_HEADER] = p2.slug
        request.user = self.user
        _add_session(request)

        SlugMiddleware(lambda r: None).process_request(request)

        self.assertEqual(request.current_project.pk, p2.pk)
        self.assertEqual(request.slug, p2.slug)
        self.assertEqual(request.session.get("current_project_id"), p2.id)

    def test_x_project_slug_ignored_for_foreign_project(self):
        uid = uuid.uuid4().hex[:8]
        user_model = get_user_model()
        pt_user = user_model.objects.create_user(username=f"pt_hdr_{uid}", password="testpass12345")
        assign_role(pt_user, "penetration_tester")
        own = self.data_generator.project
        own.users.add(pt_user)
        foreign = Project.objects.create(
            slug=f"foreign-proj-{uid}",
            name=f"Foreign {uid}",
            insert_date=timezone.now(),
        )

        request = self.factory.get("/profile/")
        request.META[X_PROJECT_SLUG_HEADER] = foreign.slug
        request.user = pt_user
        _add_session(request)

        SlugMiddleware(lambda r: None).process_request(request)

        self.assertNotEqual(request.current_project.pk, foreign.pk)
        self.assertEqual(request.current_project.pk, own.pk)

    def test_slug_in_url_wins_over_header(self):
        uid = uuid.uuid4().hex[:8]
        p_url = Project.objects.create(
            slug=f"url-proj-{uid}",
            name=f"Url Project {uid}",
            insert_date=timezone.now(),
        )
        p_url.users.add(self.user)
        p_header = Project.objects.create(
            slug=f"hdr-only-{uid}",
            name=f"Hdr Project {uid}",
            insert_date=timezone.now(),
        )
        p_header.users.add(self.user)

        path = reverse("dashboardIndex", kwargs={"slug": p_url.slug})
        request = self.factory.get(path)
        request.META[X_PROJECT_SLUG_HEADER] = p_header.slug
        request.user = self.user
        _add_session(request)

        SlugMiddleware(lambda r: None).process_request(request)

        self.assertEqual(request.current_project.pk, p_url.pk)

    def test_query_param_mismatch_ignores_header(self):
        uid = uuid.uuid4().hex[:8]
        query_project = Project.objects.create(
            slug=f"query-proj-{uid}",
            name=f"Query Project {uid}",
            insert_date=timezone.now(),
        )
        query_project.users.add(self.user)
        header_project = Project.objects.create(
            slug=f"header-proj-{uid}",
            name=f"Header Project {uid}",
            insert_date=timezone.now(),
        )
        header_project.users.add(self.user)

        request = self.factory.get("/profile/", {PROJECT_CONTEXT_QUERY_PARAM: query_project.slug})
        request.META[X_PROJECT_SLUG_HEADER] = header_project.slug
        request.user = self.user
        _add_session(request)

        SlugMiddleware(lambda r: None).process_request(request)

        self.assertEqual(request.current_project.pk, query_project.pk)

    def test_resolver_match_slug_is_used_before_path_resolve(self):
        uid = uuid.uuid4().hex[:8]
        p2 = Project.objects.create(
            slug=f"resolver-proj-{uid}",
            name=f"Resolver Project {uid}",
            insert_date=timezone.now(),
        )
        p2.users.add(self.user)

        request = self.factory.get("/profile/")
        request.path_info = "/non-existing-path/"
        request.resolver_match = resolve(reverse("dashboardIndex", kwargs={"slug": p2.slug}))
        request.user = self.user
        _add_session(request)

        SlugMiddleware(lambda r: None).process_request(request)

        self.assertEqual(request.current_project.pk, p2.pk)
        self.assertEqual(request.slug, p2.slug)


class SlugMiddlewareQueryParamTestCase(BaseTestCase):
    """SlugMiddleware resolves project from ?project= on routes without path slug."""

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()

    def test_query_param_sets_current_project_when_allowed(self):
        uid = uuid.uuid4().hex[:8]
        p2 = Project.objects.create(
            slug=f"qp-proj-{uid}",
            name=f"QP Project {uid}",
            insert_date=timezone.now(),
        )
        p2.users.add(self.user)

        request = self.factory.get("/profile/", {PROJECT_CONTEXT_QUERY_PARAM: p2.slug})
        request.user = self.user
        _add_session(request)

        SlugMiddleware(lambda r: None).process_request(request)

        self.assertEqual(request.current_project.pk, p2.pk)
        self.assertEqual(request.slug, p2.slug)

    def test_query_param_ignored_for_foreign_project(self):
        uid = uuid.uuid4().hex[:8]
        user_model = get_user_model()
        pt_user = user_model.objects.create_user(username=f"pt_qp_{uid}", password="testpass12345")
        assign_role(pt_user, "penetration_tester")
        own = self.data_generator.project
        own.users.add(pt_user)
        foreign = Project.objects.create(
            slug=f"foreign-qp-{uid}",
            name=f"Foreign QP {uid}",
            insert_date=timezone.now(),
        )

        request = self.factory.get("/profile/", {PROJECT_CONTEXT_QUERY_PARAM: foreign.slug})
        request.user = pt_user
        _add_session(request)

        SlugMiddleware(lambda r: None).process_request(request)

        self.assertNotEqual(request.current_project.pk, foreign.pk)
        self.assertEqual(request.current_project.pk, own.pk)

    def test_profile_page_body_reflects_query_param_project(self):
        uid = uuid.uuid4().hex[:8]
        p2 = Project.objects.create(
            slug=f"prof-qp-{uid}",
            name=f"Prof QP {uid}",
            insert_date=timezone.now(),
        )
        p2.users.add(self.user)
        self.client.force_login(self.user)
        url = reverse("profile") + f"?{PROJECT_CONTEXT_QUERY_PARAM}={p2.slug}"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertIn(f'data-project-slug="{p2.slug}"'.encode(), response.content)


class SetCurrentProjectTestCase(BaseTestCase):
    def test_set_current_project_bridge_sets_storage_script_without_cookie(self):
        slug = self.data_generator.project.slug
        url = reverse("set_current_project", kwargs={"slug": slug})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("currentProjectId", response.cookies)
        content = response.content.decode()
        self.assertIn("rengine-current-project-slug", content)
        self.assertIn(slug, content)
        self.assertIn(reverse("dashboardIndex", kwargs={"slug": slug}), content)

    def test_set_current_project_forbidden_for_foreign_project(self):
        uid = uuid.uuid4().hex[:8]
        user_model = get_user_model()
        pt_user = user_model.objects.create_user(username=f"pt_set_{uid}", password="testpass12345")
        assign_role(pt_user, "penetration_tester")
        own = self.data_generator.project
        own.users.add(pt_user)
        foreign = Project.objects.create(
            slug=f"no-access-{uid}",
            name=f"No Access {uid}",
            insert_date=timezone.now(),
        )
        self.client.force_login(pt_user)
        url = reverse("set_current_project", kwargs={"slug": foreign.slug})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("page_not_found"), response.url or "")
