from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('startScan', '0057_auto_20231201_2354'),  # Replace with the latest migration
    ]

    operations = [
        # 1. Create the new PortInfo model
        migrations.CreateModel(
            name='PortInfo',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('service_name', models.CharField(max_length=100, blank=True, null=True)),
                ('description', models.CharField(max_length=1000, blank=True, null=True)),
                ('ip_address', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.ipaddress')),
                ('port', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.port')),
            ],
            options={
                'unique_together': {('ip_address', 'port')},
            },
        ),
        
        # 2. Remove the old M2M field
        migrations.RemoveField(
            model_name='ipaddress',
            name='ports',
        ),
        
        # 3. Add new M2M field with through
        migrations.AddField(
            model_name='ipaddress',
            name='ports',
            field=models.ManyToManyField(through='startScan.PortInfo', related_name='ip_addresses', to='startScan.port'),
        ),
        
        # 4. Remove old fields from Port
        migrations.RemoveField(
            model_name='Port',
            name='service_name',
        ),
        migrations.RemoveField(
            model_name='Port',
            name='description',
        ),
    ] 
