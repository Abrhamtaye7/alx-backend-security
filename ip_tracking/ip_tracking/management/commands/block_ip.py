from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError

from ip_tracking.models import BlockedIP


class Command(BaseCommand):
    help = "Add an IP address to the BlockedIP blacklist."

    def add_arguments(self, parser):
        parser.add_argument("ip_address", type=str, help="IPv4 or IPv6 address to block")

    def handle(self, *args, **options):
        ip = options["ip_address"].strip()

        # Validate IP format
        try:
            validate_ipv46_address(ip)
        except ValidationError:
            raise CommandError(f"Invalid IP address: {ip}")

        obj, created = BlockedIP.objects.get_or_create(ip_address=ip)

        if created:
            self.stdout.write(self.style.SUCCESS(f"Blocked IP added: {ip}"))
        else:
            self.stdout.write(self.style.WARNING(f"IP already blocked: {ip}"))
