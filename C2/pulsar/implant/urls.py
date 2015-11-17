try:
    from django.conf.urls import *
except ImportError:  # django < 1.4
    from django.conf.urls.defaults import *

# place app url patterns here
from . import views

urlpatterns = [
    # URL pattern for the UserListView
    url(
        regex=r'^$',
        view=views.ImplantListView.as_view(),
        name='list'
    ),

    url(
        regex=r'^group/$',
        view=views.GroupListView.as_view(),
        name='group_list'
    ),

    url(
        regex=r'^group/create/$',
        view=views.GroupCreateView.as_view(),
        name='group_create'
    ),

    url(
        regex=r'^group/(?P<slug>[\w-]+)/edit/$',
        view=views.GroupUpdateView.as_view(),
        name='group_update'
    ),

    url(
    	regex=r'^group/([\w-]+)/$',
    	view=views.ImplantListByGroupView.as_view(),
    	name='list_by_group'
    ),

    url(
        regex=r'^(?P<pk>\d+)/$',
        view=views.ImplantUpdateView.as_view(),
        name='edit'
    ),

    url(
        regex=r'^beacon/$',
        view=views.ImplantBeaconView.as_view(),
        name='beacon'
    ),

    url(
        regex=r'^command/$',
        view=views.AcknowledgeCommandsView.as_view(),
        name='acknowledge_commands'
    ),

    url(
        regex=r'^interactive/(?P<pk>\d+)/$',
        view=views.GoInteractiveView.as_view(),
        name='go_interactive'
    ),

    url(
        regex=r'^end_interactive/(?P<pk>\d+)/$',
        view=views.EndInteractiveView.as_view(),
        name='end_interactive'
    ),

    url(
        regex=r'^uninstall/(?P<pk>\d+)/$',
        view=views.UninstallView.as_view(),
        name='uninstall'
    ),

    url(
        regex=r'^binaries/$',
        view=views.ProvisionedBinaryListView.as_view(),
        name='binaries_list',
    ),

    url(
        regex=r'^binaries/create/$',
        view=views.ProvisionedBinaryCreateView.as_view(),
        name='binary_create',
    ),

    url(
        regex=r'^binaries/(?P<pk>\d+)/delete/$',
        view=views.ProvisionedBinaryDeleteView.as_view(),
        name='binary_delete',
    ),
]
