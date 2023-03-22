<?php
/*
 -------------------------------------------------------------------------
 MFA plugin for GLPI
 Copyright (C) 2022 by the TICgal Team.
 https://www.tic.gal
 -------------------------------------------------------------------------
 LICENSE
 This file is part of the MFA plugin.
 MFA plugin is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.
 MFA plugin is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 You should have received a copy of the GNU General Public License
 along with MFA. If not, see <http://www.gnu.org/licenses/>.
 --------------------------------------------------------------------------
 @package   MFA
 @author    the TICgal team
 @copyright Copyright (c) 2022 TICgal team
 @license   AGPL License 3.0 or (at your option) any later version
				http://www.gnu.org/licenses/agpl-3.0-standalone.html
 @link      https://www.tic.gal
 @since     2022
 ----------------------------------------------------------------------
*/

if (!defined('GLPI_ROOT')) {
	die("Sorry. You can't access directly to this file");
}

class PluginMfaNotificationTargetMfa extends NotificationTarget
{

	public function getEvents()
	{
		return [
			'securitycodegenerate' => __('One-Time Security Code generated', 'mfa'),
		];
	}

	public function addNotificationTargets($entity)
	{
		$this->addTarget(Notification::USER, User::getTypeName(1));
	}

	public function addSpecificTargets($data, $options)
	{
		//Look for all targets whose type is Notification::ITEM_USER
		switch ($data['type']) {
			case Notification::USER_TYPE:
				switch ($data['items_id']) {
					case Notification::USER:
						$usertype = self::GLPI_USER;
						// Send to user without any check on profile / entity
						// Do not set users_id
						$user = new User();
						$user->getFromDB($this->obj->fields['users_id']);
						$data = [
							'name'     => $user->getName(),
							'email'    => $user->getDefaultEmail(),
							'language' => $user->getField('language'),
							'usertype' => $usertype
						];
						$this->addToRecipientsList($data);
				}
		}
	}

	public function addDataForTemplate($event, $options = [])
	{
		$events = $this->getEvents();

		$this->data['##mfa.action##'] = $events[$event];
		$this->data['##mfa.code##'] = $this->obj->getField("code");

		$this->getTags();
		foreach ($this->tag_descriptions[NotificationTarget::TAG_LANGUAGE] as $tag => $values) {
			if (!isset($this->data[$tag])) {
				$this->data[$tag] = $values['label'];
			}
		}
	}

	public function getTags()
	{

		// Common value tags
		$tags = [
			'mfa.code' => __('One-Time Security Code', 'mfa'),
			'mfa.action' => _n('Event', 'Events', 1),
		];

		foreach ($tags as $tag => $label) {
			$this->addTagToList(
				[
					'tag'    => $tag,
					'label'  => $label,
					'value'  => true,
				]
			);
		}

		$lang_tags = [
			'mfa.information' => __('This is your security code:', 'mfa'),
			'mfa.expiration' => __('Please verify it as soon as possible; this OTP will expire quickly.', 'mfa'),
		];

		foreach ($lang_tags as $tag => $label) {
			$this->addTagToList(
				[
					'tag'    => $tag,
					'label'  => $label,
					'value'  => false,
					'lang'   => true,
				]
			);
		}

		asort($this->tag_descriptions);
		return $this->tag_descriptions;
	}

	public static function install(Migration $migration)
	{
		global $DB;

		$migration->displayMessage("Migrate PluginMfaMfa notifications");

		$template     = new NotificationTemplate();
		$translation  = new NotificationTemplateTranslation();
		$notification = new Notification();
		$n_n_template = new Notification_NotificationTemplate();
		$target       = new NotificationTarget();

		$itemtype = PluginMfaMfa::getType();
		$label = 'One-Time Security Code generated - MFA';

		$templates_id = false;

		$result = $DB->request([
			'SELECT' => 'id',
			'FROM' => NotificationTemplate::getTable(),
			'WHERE' => [
				'itemtype' => $itemtype,
				'name' => $label
			]
		]);

		if (count($result) > 0) {
			$data = $result->current();
			$templates_id = $data['id'];
		} else {
			$templates_id = $template->add([
				'name' => $label,
				'itemtype' => $itemtype,
				'date_mod' => $_SESSION['glpi_currenttime'],
				'comment' => '',
				'css' => '',
			]);
		}

		if ($templates_id) {
			$translation_count = countElementsInTable($translation->getTable(), ['notificationtemplates_id' => $templates_id]);
			if ($translation_count == 0) {
				$translation->add([
					'notificationtemplates_id' => $templates_id,
					'language' => '',
					'subject' => 'One-Time Security Code generated',
					'content_text' => '##mfa.code##',
					'content_html' => '##lang.mfa.information##<br>##mfa.code##<br>##lang.mfa.expiration##'
				]);
			}

			$notications_count = countElementsInTable($notification->getTable(), ['itemtype' => $itemtype, 'event' => 'securitycodegenerate', 'name' => $label]);

			if ($notications_count == 0) {
				$notification_id = $notification->add([
					'name' => $label,
					'entities_id' => 0,
					'itemtype' => $itemtype,
					'event' => 'securitycodegenerate',
					'comment' => '',
					'is_recursive' => 1,
					'is_active' => 1,
					'date_mod' => $_SESSION['glpi_currenttime'],
				]);

				$n_n_template->add([
					'notifications_id' => $notification_id,
					'mode' => Notification_NotificationTemplate::MODE_MAIL,
					'notificationtemplates_id' => $templates_id,
				]);

				$target->add([
					'notifications_id' => $notification_id,
					'type' => Notification::USER_TYPE,
					'items_id' => 19
				]);
			}
		}
	}
}
