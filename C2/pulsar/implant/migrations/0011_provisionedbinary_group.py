# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('implant', '0010_provisionedbinary_configuration'),
    ]

    operations = [
        migrations.AddField(
            model_name='provisionedbinary',
            name='group',
            field=models.ForeignKey(default=1, to='implant.Group'),
            preserve_default=False,
        ),
    ]
