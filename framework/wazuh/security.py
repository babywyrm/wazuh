# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re

from api.authentication import AuthenticationManager
from wazuh import common
from wazuh.exception import WazuhError, create_exception_dic
from wazuh.rbac import orm
from wazuh.rbac.decorators import expose_resources, list_handler_with_denied, list_handler_no_denied
from wazuh.rbac.orm import SecurityError
from wazuh.utils import process_array

# Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character:
_user_password = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[_@$!%*?&-])[A-Za-z\d@$!%*?&-_]{8,}$')


@expose_resources(actions=['security:read'], resources=['user:id:*'], target_params=['username_list'],
                  post_proc_func=list_handler_no_denied)
def get_users_all(username_list=None, offset=0, limit=common.database_limit, sort_by=None,
                  sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Get the information of all users

    :param username_list: Name of the user
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    with AuthenticationManager() as auth:
        for username in username_list:
            user = auth.get_users(username)
            if user:
                affected_items.append(user)

    affected_items = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                                   complementary_search=complementary_search, sort_by=sort_by,
                                   sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    return {'affected_items': affected_items,
            'failed_items': list(),
            'str_priority': ['All available users were shown', '', '']}


@expose_resources(actions=['security:read'], resources=['user:id:{username_list}'], target_params=['username_list'],
                  post_proc_func=list_handler_with_denied)
def get_users(username_list=None, offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Get the information of a specified user

    :param username_list: Name of the user
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    failed_items = list()
    with AuthenticationManager() as auth:
        for username in username_list:
            user = auth.get_users(username)
            affected_items.append(user) if user \
                else failed_items.append(create_exception_dic(username, WazuhError(5001)))

    affected_items = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                                   complementary_search=complementary_search, sort_by=sort_by,
                                   sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    return {'affected_items': affected_items,
            'failed_items': failed_items,
            'str_priority': ['All specified users were show',
                             'Some users could not be show', 'No user were shown']}


@expose_resources(actions=['security:create_user'], resources=['*:*:*'], target_params=['*'],
                  post_proc_func=list_handler_no_denied)
def create_user(username: str = None, password: str = None):
    """Create a new user

    :param username: Name for the new user
    :param password: Password for the new user
    :return: Status message
    """
    if not _user_password.match(password):
        raise WazuhError(5007)

    result = None
    with AuthenticationManager() as auth:
        if auth.add_user(username, password):
            result = auth.get_users(username)

    if result is None:
        raise WazuhError(5000, extra_message='The user \'{}\' could not be created'.format(username))

    return {'affected_items': [result],
            'failed_items': list(),
            'str_priority': ['User created correctly', '', '']}


@expose_resources(actions=['security:read'], resources=['user:id:{username}'], target_params=['username'],
                  post_proc_func=list_handler_no_denied)
def update_user(username=None, password=None):
    """Update a specified user

    :param username: Name for the new user
    :param password: Password for the new user
    :return: Status message
    """
    if not _user_password.match(password):
        raise WazuhError(5007)

    with AuthenticationManager() as auth:
        query = auth.update_user(username[0], password)
        if query is False:
            raise WazuhError(5001, extra_message='The user \'{}\' not exist'.format(username[0]))
        elif query == 'admin':
            raise WazuhError(5004, extra_message='The users wazuh and wazuh-app can not be updated')

    return {'affected_items': auth.get_users(username[0]),
            'failed_items': list(),
            'str_priority': ['User modified correctly', '', '']}


@expose_resources(actions=['security:read'], resources=['user:id:{username_list}'], target_params=['username_list'],
                  post_proc_func=list_handler_no_denied)
def delete_user(username: str):
    """Delete a specified user

    :param username: Name of the user
    :return: Status message
    """
    with AuthenticationManager() as auth:
        query = auth.delete_user(username)
        if query is False:
            raise WazuhError(5001, extra_message='The user \'{}\' not exist'.format(username))
        elif query == 'admin':
            raise WazuhError(5004, extra_message='The users wazuh and wazuh-app can not be removed')

    return {'affected_items': username,
            'failed_items': list(),
            'str_priority': ['User deleted correctly', '', '']}


@expose_resources(actions=['security:read'], resources=['role:id:{role_ids}'], target_params=['role_ids'],
                  post_proc_func=list_handler_with_denied)
def get_roles(role_ids=None, offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Returns information from all system roles, does not return information from its associated policies

    :param role_ids: List of roles ids.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    failed_items = list()
    with orm.RolesManager() as rm:
        for r_id in role_ids:
            role = rm.get_role_id(int(r_id))
            if role != SecurityError.ROLE_NOT_EXIST:
                dict_role = role.to_dict()
                for index, policy in enumerate(dict_role['policies']):
                    dict_role['policies'][index]['policy'] = json.loads(dict_role['policies'][index]['policy'])
                affected_items.append(dict_role)
            else:
                # Role id does not exist
                failed_items.append(create_exception_dic(r_id, WazuhError(4002)))

    affected_items = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                                   complementary_search=complementary_search, sort_by=sort_by,
                                   sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    return {'affected_items': affected_items,
            'failed_items': failed_items,
            'str_priority': ['All specified roles were show',
                             'Some roles could not be show', 'No role were shown']}


@expose_resources(actions=['security:read'], resources=['role:id:*'], target_params=['role_ids'],
                  post_proc_func=list_handler_no_denied)
def get_roles_all(role_ids=None, offset=0, limit=common.database_limit, sort_by=None,
                  sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Returns information from all system roles, does not return information from its associated policies

    :param role_ids: List of roles ids. (All)
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    with orm.RolesManager() as rm:
        for r_id in role_ids:
            role = rm.get_role_id(int(r_id))
            if role != SecurityError.ROLE_NOT_EXIST:
                dict_role = role.to_dict()
                dict_role.pop('policies', None)
                affected_items.append(dict_role)

    affected_items = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                                   complementary_search=complementary_search, sort_by=sort_by,
                                   sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    return {'affected_items': affected_items,
            'failed_items': list(),
            'str_priority': ['All available roles were shown', '', '']}


@expose_resources(actions=['security:delete'], resources=['role:id:{role_ids}'], target_params=['role_ids'],
                  post_proc_func=list_handler_with_denied)
def remove_roles(role_ids):
    """Removes a certain role from the system

    :param role_ids: List of roles ids.
    :return Result of operation.
    """
    affected_items = list()
    failed_items = list()
    with orm.RolesManager() as rm:
        for r_id in role_ids:
            result = rm.delete_role(int(r_id))
            if result == SecurityError.ADMIN_RESOURCES:
                failed_items.append(create_exception_dic(r_id, WazuhError(4008)))
            elif result is False:
                failed_items.append(create_exception_dic(r_id, WazuhError(4002)))
            else:
                affected_items.append(r_id)

    return {'affected_items': affected_items,
            'failed_items': failed_items,
            'str_priority': ['All specified roles were deleted',
                             'Some roles could not be delete', 'No role were deleted']}


@expose_resources(actions=['security:delete'], resources=['role:id:*'], target_params=['role_ids'],
                  post_proc_func=list_handler_no_denied)
def remove_roles_all(role_ids=None):
    """Removes all roles from the system

    :param role_ids: List of roles ids. (All)
    :return Result of operation.
    """
    affected_items = list()
    with orm.RolesManager() as rm:
        for r_id in role_ids:
            result = rm.delete_role(int(r_id))
            if result and result != SecurityError.ADMIN_RESOURCES:
                affected_items.append(r_id)

    return {'affected_items': affected_items,
            'failed_items': list(),
            'str_priority': ['All available roles were deleted', '', '']}


@expose_resources(actions=['security:create'], resources=['*:*:*'], target_params=['*'],
                  post_proc_func=list_handler_no_denied)
def add_role(name=None, rule=None):
    """Creates a role in the system

    :param name: The new role name
    :param rule: The new rule
    :return Role information.
    """
    with orm.RolesManager() as rm:
        status = rm.add_role(name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            raise WazuhError(4005)
        elif status == SecurityError.INVALID:
            raise WazuhError(4003)

    return {'affected_items': [rm.get_role(name=name).to_dict()],
            'failed_items': list(),
            'str_priority': ['Role created correctly', '', '']}


@expose_resources(actions=['security:update'], resources=['role:id:{role_id}'], target_params=['role_id'],
                  post_proc_func=list_handler_no_denied)
def update_role(role_id=None, name=None, rule=None):
    """Updates a role in the system

    :param role_id: Role id to be update
    :param name: The new role name
    :param rule: The new rule
    :return Role information.
    """
    if name is None and rule is None:
        raise WazuhError(4001)

    with orm.RolesManager() as rm:
        status = rm.update_role(role_id=int(role_id[0]), name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            raise WazuhError(4005)
        elif status == SecurityError.INVALID:
            raise WazuhError(4003)
        elif status == SecurityError.ROLE_NOT_EXIST:
            raise WazuhError(4002)
        elif status == SecurityError.ADMIN_RESOURCES:
            raise WazuhError(4008)

    return {'affected_items': [rm.get_role_id(role_id=role_id[0]).to_dict()],
            'failed_items': list(),
            'str_priority': ['Role updated correctly', '', '']}


@expose_resources(actions=['security:read'], resources=['policy:id:{policy_ids}'], target_params=['policy_ids'],
                  post_proc_func=list_handler_with_denied)
def get_policies(policy_ids, offset=0, limit=common.database_limit, sort_by=None,
                 sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Returns the information of a certain policy

    :param policy_ids: ID of the policy on which the information will be collected
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    failed_items = list()
    with orm.PoliciesManager() as pm:
        for p_id in policy_ids:
            policy = pm.get_policy_id(int(p_id))
            if policy != SecurityError.POLICY_NOT_EXIST:
                dict_policy = policy.to_dict()
                for index, policy in enumerate(dict_policy['roles']):
                    dict_policy['roles'][index]['rule'] = json.loads(dict_policy['roles'][index]['rule'])
                affected_items.append(dict_policy)
            else:
                # Policy id does not exist
                failed_items.append(create_exception_dic(p_id, WazuhError(4007)))

    affected_items = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                                   complementary_search=complementary_search, sort_by=sort_by,
                                   sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    return {'affected_items': affected_items,
            'failed_items': failed_items,
            'str_priority': ['All specified policies were shown',
                             'Some policies could not be shown', 'No policy were shown']}


@expose_resources(actions=['security:read'], resources=['policy:id:*'], target_params=['policy_ids'],
                  post_proc_func=list_handler_no_denied)
def get_policies_all(policy_ids=None, offset=0, limit=common.database_limit, sort_by=None,
                     sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Here we will be able to obtain all policies

    :param policy_ids: Lists of IDs of the policies on which the information will be collected
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    with orm.PoliciesManager() as pm:
        for p_id in policy_ids:
            policy = pm.get_policy_id(int(p_id))
            if policy != SecurityError.POLICY_NOT_EXIST:
                dict_policy = policy.to_dict()
                dict_policy.pop('roles', None)
                affected_items.append(dict_policy)

    affected_items = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                                   complementary_search=complementary_search, sort_by=sort_by,
                                   sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    return {'affected_items': affected_items,
            'failed_items': list(),
            'str_priority': ['All available policies were shown', '', '']}


@expose_resources(actions=['security:delete'], resources=['policy:id:{policy_ids}'], target_params=['policy_ids'],
                  post_proc_func=list_handler_with_denied)
def remove_policies(policy_ids=None):
    """Removes a certain policy from the system

    :param policy_ids: ID of the policy to be removed
    :return Result of operation.
    """
    affected_items = list()
    failed_items = list()
    with orm.PoliciesManager() as pm:
        for p_id in policy_ids:
            result = pm.delete_policy(int(p_id))
            if result == SecurityError.ADMIN_RESOURCES:
                failed_items.append(create_exception_dic(p_id, WazuhError(4008)))
            elif result is False:
                failed_items.append(create_exception_dic(p_id, WazuhError(4007)))
            else:
                affected_items.append(p_id)

    return {'affected_items': affected_items,
            'failed_items': failed_items,
            'str_priority': ['All specified policies were deleted',
                             'Some policies could not be deleted', 'No policies were deleted']}


@expose_resources(actions=['security:delete'], resources=['policy:id:*'], target_params=['policy_ids'],
                  post_proc_func=list_handler_no_denied)
def remove_policies_all(policy_ids=None):
    """Removes a list of policies from the system

    :param policy_ids: List of policies to be removed
    :return Result of operation.
    """
    affected_items = list()
    with orm.PoliciesManager() as pm:
        for p_id in policy_ids:
            result = pm.delete_policy(int(p_id))
            if result and result != SecurityError.ADMIN_RESOURCES:
                affected_items.append(p_id)

    return {'affected_items': affected_items,
            'failed_items': list(),
            'str_priority': ['All available policies were deleted', '', '']}


@expose_resources(actions=['security:create'], resources=['*:*:*'], target_params=['*'],
                  post_proc_func=list_handler_no_denied)
def add_policy(name=None, policy=None):
    """Creates a policy in the system

    :param name: The new policy name
    :param policy: The new policy
    :return Policy information.
    """
    with orm.PoliciesManager() as pm:
        status = pm.add_policy(name=name, policy=policy)
        if status == SecurityError.ALREADY_EXIST:
            raise WazuhError(4009)
        elif status == SecurityError.INVALID:
            raise WazuhError(4006)

    return {'affected_items': [pm.get_policy(name=name).to_dict()],
            'failed_items': list(),
            'str_priority': ['Policy created correctly', '', '']}


@expose_resources(actions=['security:update'], resources=['policy:id:{policy_id}'], target_params=['policy_id'],
                  post_proc_func=list_handler_no_denied)
def update_policy(policy_id=None, name=None, policy=None):
    """Updates a policy in the system

    :param policy_id: Policy id to be update
    :param name: The new policy name
    :param policy: The new policy
    :return Policy information.
    """
    if name is None and policy is None:
        raise WazuhError(4001)

    with orm.PoliciesManager() as pm:
        status = pm.update_policy(policy_id=int(policy_id[0]), name=name, policy=policy)
        if status == SecurityError.ALREADY_EXIST:
            raise WazuhError(4013)
        elif status == SecurityError.INVALID:
            raise WazuhError(4006)
        elif status == SecurityError.POLICY_NOT_EXIST:
            raise WazuhError(4007)
        elif status == SecurityError.ADMIN_RESOURCES:
            raise WazuhError(4008)

    return {'affected_items': [pm.get_policy_id(policy_id[0]).to_dict()],
            'failed_items': list(),
            'str_priority': ['Policy updated correctly', '', '']}


@expose_resources(actions=['security:update'], resources=['role:id:{role_id}', 'policy:id:{policy_ids}'],
                  target_params=['role_id', 'policy_ids'], post_proc_func=list_handler_with_denied)
def set_role_policy(role_id, policy_ids):
    """Create a relationship between a role and a policy

    :param role_id: The new role_id
    :param policy_ids: List of policies ids
    :return Role-Policies information.
    """
    affected_items = list()
    failed_items = list()
    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policy_ids:
            role_policy = rpm.add_policy_to_role(role_id=role_id[0], policy_id=policy_id)
            if role_policy == SecurityError.ALREADY_EXIST:
                failed_items.append(
                    create_exception_dic(
                        'role {}: policy {}'.format(role_id[0], policy_id),
                        WazuhError(4011)))
            elif role_policy == SecurityError.ROLE_NOT_EXIST:
                failed_items.append(
                    create_exception_dic(
                        'role {}: policy {}'.format(role_id[0], policy_id),
                        WazuhError(4002)))
            elif role_policy == SecurityError.POLICY_NOT_EXIST:
                failed_items.append(
                    create_exception_dic(
                        'role {}: policy {}'.format(role_id[0], policy_id),
                        WazuhError(4007)))
            elif role_policy == SecurityError.ADMIN_RESOURCES:
                failed_items.append(
                    create_exception_dic(
                        'role {}: policy {}'.format(role_id[0], policy_id),
                        WazuhError(4008)))
            else:
                affected_items.append('role {}: policy {}'.format(role_id[0], policy_id))

    return {'affected_items': affected_items,
            'failed_items': failed_items,
            'str_priority': ['All roles and policies were linked',
                             'Some roles and policies could not be linked', 'No links created']}


@expose_resources(actions=['security:delete'], resources=['role:id:{role_id}', 'policy:id:{policy_ids}'],
                  target_params=['role_id', 'policy_ids'], post_proc_func=list_handler_with_denied)
def remove_role_policy(role_id, policy_ids):
    """Removes a relationship between a role and a policy

    :param role_id: The new role_id
    :param policy_ids: List of policies ids
    :return Result of operation.
    """
    affected_items = list()
    failed_items = list()
    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policy_ids:
            role_policy = rpm.remove_policy_in_role(role_id=role_id[0], policy_id=policy_id)
            if role_policy == SecurityError.INVALID:
                failed_items.append(
                    create_exception_dic(
                        'role {}: policy {}'.format(role_id[0], policy_id),
                        WazuhError(4010)))
            elif role_policy == SecurityError.ROLE_NOT_EXIST:
                failed_items.append(
                    create_exception_dic(
                        'role {}: policy {}'.format(role_id[0], policy_id),
                        WazuhError(4002)))
            elif role_policy == SecurityError.POLICY_NOT_EXIST:
                failed_items.append(
                    create_exception_dic(
                        'role {}: policy {}'.format(role_id[0], policy_id),
                        WazuhError(4007)))
            elif role_policy == SecurityError.ADMIN_RESOURCES:
                failed_items.append(
                    create_exception_dic(
                        'role {}: policy {}'.format(role_id[0], policy_id),
                        WazuhError(4008)))
            else:
                affected_items.append('role {}: policy {}'.format(role_id[0], policy_id))

    return {'affected_items': affected_items,
            'failed_items': failed_items,
            'str_priority': ['All links between roles and policies were deleted',
                             'Some links between roles and policies could not be deleted', 'No links deleted']}