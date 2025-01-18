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
            ],
        ),
        
        # 2. Remove the fields from the Port model that are moved to PortInfo
        migrations.RemoveField(
            model_name='Port',
            name='service_name',
        ),
        migrations.RemoveField(
            model_name='Port',
            name='description',
        ),
        
        # 3. Add the ForeignKey relationships for PortInfo
        migrations.AddField(
            model_name='PortInfo',
            name='ip_address',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.ipaddress'),
        ),
        migrations.AddField(
            model_name='PortInfo',
            name='port',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='startScan.port'),
        ),
        
        # 4. Modify the ManyToMany relationship to use the through model
        migrations.AlterField(
            model_name='IpAddress',
            name='ports',
            field=models.ManyToManyField(through='startScan.PortInfo', related_name='ip_addresses', to='startScan.Port'),
        ),
        
        # 5. Add the unique_together constraint
        migrations.AlterUniqueTogether(
            name='PortInfo',
            unique_together={('ip_address', 'port')},
        ),
    ] 