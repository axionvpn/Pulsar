# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('implant', '0008_provisionedbinary_label'),
    ]

    operations = [
        migrations.AddField(
            model_name='provisionedbinary',
            name='binary_type',
            field=models.CharField(default=b'CONSOLE', max_length=16, choices=[(b'CONSOLE', b'Console')]),
        ),
    ]
