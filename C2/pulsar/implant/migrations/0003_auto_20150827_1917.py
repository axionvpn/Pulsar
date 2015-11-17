# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('implant', '0002_auto_20150827_1851'),
    ]

    operations = [
        migrations.AlterField(
            model_name='implant',
            name='ip_address',
            field=models.GenericIPAddressField(null=True, unpack_ipv4=True, blank=True),
        ),
    ]
