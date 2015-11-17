#!/usr/bin/env python

import os
import sys

proj_dir = os.path.expanduser(os.environ['PROJECT_DIR'])
sys.path.append(proj_dir)

import django
django.setup()

from django.contrib.auth import get_user_model
User = get_user_model()

u, _ = User.objects.get_or_create(username=os.environ['ADMIN_USERNAME'])
u.is_staff = u.is_superuser = True
u.set_password(os.environ['ADMIN_PASSWORD'])
u.save()
