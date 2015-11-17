# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.utils.timezone
import model_utils.fields
import django.core.validators
import uuidfield.fields


class Migration(migrations.Migration):

    dependencies = [
        ('implant', '0006_implant_uninstalled'),
    ]

    operations = [
        migrations.CreateModel(
            name='ProvisionedBinary',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('created', model_utils.fields.AutoCreatedField(default=django.utils.timezone.now, verbose_name='created', editable=False)),
                ('modified', model_utils.fields.AutoLastModifiedField(default=django.utils.timezone.now, verbose_name='modified', editable=False)),
                ('uuid', uuidfield.fields.UUIDField(unique=True, max_length=32, editable=False, blank=True)),
                ('beacon_time', models.PositiveIntegerField()),
                ('beacon_jitter', models.PositiveIntegerField()),
                ('local_port', models.PositiveIntegerField(validators=[django.core.validators.MaxValueValidator(65535, message=b'Port numbers must be 0-65535')])),
                ('relay_url', models.CharField(max_length=255)),
                ('binary_file', models.FileField(upload_to=b'binaries', null=True, editable=False, blank=True)),
            ],
            options={
                'verbose_name_plural': 'Provisioned binaries',
            },
        ),
    ]
