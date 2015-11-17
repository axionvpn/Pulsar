# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('implant', '0007_provisionedbinary'),
    ]

    operations = [
        migrations.AddField(
            model_name='provisionedbinary',
            name='label',
            field=models.CharField(default='', max_length=255),
            preserve_default=False,
        ),
    ]
