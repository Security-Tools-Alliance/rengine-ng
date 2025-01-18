from django.db import migrations

def migrate_port_data(apps, schema_editor):
    IpAddress = apps.get_model('startScan', 'IpAddress')
    PortInfo = apps.get_model('startScan', 'PortInfo')
    
    # Pour chaque IP
    for ip in IpAddress.objects.all():
        # Pour chaque port associé à cette IP via l'ancienne relation
        for port in ip.ports.through.objects.filter(ipaddress=ip):
            # Créer une entrée PortInfo
            PortInfo.objects.get_or_create(
                ip_address=ip,
                port=port,
                defaults={
                    'service_name': 'unknown',
                    'description': ''
                }
            )

class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0058_port_info_model'),
    ]

    operations = [
        migrations.RunPython(migrate_port_data),
    ] 