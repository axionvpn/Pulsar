from django.contrib import admin

from .models import Implant, Group, Command, ProvisionedBinary


class GroupAdmin(admin.ModelAdmin):
	prepopulated_fields = {'slug': ('label',)}


admin.site.register(Implant)
admin.site.register(Group, GroupAdmin)
admin.site.register(Command)
admin.site.register(ProvisionedBinary)
