# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('implant', '0009_provisionedbinary_binary_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='provisionedbinary',
            name='configuration',
            field=models.FileField(upload_to=b'configurations', null=True, editable=False, blank=True),
        ),
    ]
