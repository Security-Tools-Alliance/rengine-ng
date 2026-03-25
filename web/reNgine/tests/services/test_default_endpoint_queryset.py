from reNgine.services.default_endpoint_queryset import (
    apply_endpoint_port_and_techs_related,
    apply_endpoint_techs_prefetch,
)
from startScan.models import EndPoint
from utils.test_base import BaseTestCase


class DefaultEndpointQuerysetHelpersTestCase(BaseTestCase):
    """
    Asserts queryset shape via Django private attributes (`_prefetch_related_lookups`, `query.select_related`).
    If a Django upgrade changes these, update this module alongside ORM release notes.
    """

    def test_apply_endpoint_port_and_techs_related_selects_port_and_prefetches_techs(self) -> None:
        qs = apply_endpoint_port_and_techs_related(EndPoint.objects.all())
        prefetch = getattr(qs, "_prefetch_related_lookups", ()) or ()
        flat_names: list[str] = []
        for p in prefetch:
            if isinstance(p, str):
                flat_names.append(p)
            else:
                through = getattr(p, "prefetch_through", None)
                if through:
                    flat_names.append(through)
        self.assertIn("techs", flat_names)
        sr_related = qs.query.select_related
        self.assertIsInstance(sr_related, dict)
        self.assertIn("port", sr_related)

    def test_apply_endpoint_techs_prefetch_does_not_select_port(self) -> None:
        qs = apply_endpoint_techs_prefetch(EndPoint.objects.all())
        prefetch = getattr(qs, "_prefetch_related_lookups", ()) or ()
        flat_names: list[str] = []
        for p in prefetch:
            if isinstance(p, str):
                flat_names.append(p)
            else:
                through = getattr(p, "prefetch_through", None)
                if through:
                    flat_names.append(through)
        self.assertIn("techs", flat_names)
        sr_techs = qs.query.select_related
        self.assertTrue(
            sr_techs is False or (isinstance(sr_techs, dict) and "port" not in sr_techs),
            msg="apply_endpoint_techs_prefetch must not select_related port",
        )
