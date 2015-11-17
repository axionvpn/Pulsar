# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('implant', '0004_auto_20150827_1929'),
    ]

    operations = [
        migrations.AddField(
            model_name='implant',
            name='interactive',
            field=models.BooleanField(default=False),
        ),
    ]
