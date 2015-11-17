# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('implant', '0005_implant_interactive'),
    ]

    operations = [
        migrations.AddField(
            model_name='implant',
            name='uninstalled',
            field=models.BooleanField(default=False),
        ),
    ]
