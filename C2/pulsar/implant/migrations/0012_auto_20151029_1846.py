# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.core.validators


class Migration(migrations.Migration):

    dependencies = [
        ('implant', '0011_provisionedbinary_group'),
    ]

    operations = [
        migrations.AlterField(
            model_name='provisionedbinary',
            name='binary_type',
            field=models.CharField(default=('SERVICE_x86_debug', 'Service (x86 - Debug)'), max_length=255, choices=[('SERVICE_x86_debug', 'Service (x86 - Debug)'), ('DLL_x86_release', 'DLL (x86 - Release)'), ('SERVICE_x86_release', 'Service (x86 - Release)'), ('CONSOLE_x86_release', 'Console (x86 - Release)'), ('DLL_x64_debug', 'DLL (x64 - Debug)'), ('CONSOLE_x86_debug', 'Console (x86 - Debug)'), ('DLL_x64_release', 'DLL (x64 - Release)'), ('SERVICE_x64_debug', 'Service (x64 - Debug)'), ('SERVICE_x64_release', 'Service (x64 - Release)'), ('CONSOLE_x64_release', 'Console (x64 - Release)'), ('DLL_x86_debug', 'DLL (x86 - Debug)'), ('CONSOLE_x64_debug', 'Console (x64 - Debug)')]),
        ),
        migrations.AlterField(
            model_name='provisionedbinary',
            name='local_port',
            field=models.PositiveIntegerField(default=8080, validators=[django.core.validators.MaxValueValidator(65535, message=b'Port numbers must be 0-65535')]),
        ),
    ]
