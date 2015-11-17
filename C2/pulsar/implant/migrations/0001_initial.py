# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.utils.timezone
import model_utils.fields
import django.core.validators
import uuidfield.fields


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Command',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('created', model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, verbose_name='created', editable=False)),
                ('modified', model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, verbose_name='modified', editable=False)),
                ('uuid', uuidfield.fields.UUIDField(unique=True, max_length=32, editable=False, blank=True)),
                ('status', models.IntegerField(default=0, choices=[(0, b'Created'), (1, b'Sent'), (2, b'Completed'), (3, b'Error')])),
                ('sent_at', model_utils.fields.MonitorField(default=django.utils.timezone.now, null=True, when=set([1]), monitor=b'status', blank=True)),
                ('resolved_at', model_utils.fields.MonitorField(default=django.utils.timezone.now, null=True, when=set([2, 3]), monitor=b'status', blank=True)),
                ('command_type', models.IntegerField(choices=[(0, b'Change Setting'), (1, b'Launch Payload'), (2, b'Uninstall')])),
                ('argument', models.TextField(blank=True)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Group',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('label', models.CharField(max_length=255)),
                ('slug', models.SlugField()),
            ],
        ),
        migrations.CreateModel(
            name='Implant',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('uuid', models.CharField(max_length=32)),
                ('label', models.CharField(max_length=255)),
                ('ip_address', models.GenericIPAddressField(unpack_ipv4=True)),
                ('operating_system', models.CharField(max_length=255, blank=True)),
                ('last_beacon', models.DateTimeField()),
                ('beacon_interval', models.PositiveIntegerField()),
                ('beacon_jitter', models.PositiveIntegerField()),
                ('relay_host', models.CharField(max_length=255)),
                ('relay_port', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(65535, message=b'Port numbers must be 0-65535')])),
                ('group', models.ForeignKey(to='implant.Group')),
            ],
        ),
        migrations.AddField(
            model_name='command',
            name='implant',
            field=models.ForeignKey(to='implant.Implant'),
        ),
    ]
