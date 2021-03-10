<?php

/**
 * Fired during plugin deactivation
 *
 * @link       as
 * @since      1.0.0
 *
 * @package    TBThemes_Demo_Import
 * @subpackage TBThemes_Demo_Import/includes
 */

/**
 * Fired during plugin deactivation.
 *
 * This class defines all code necessary to run during the plugin's deactivation.
 *
 * @since      1.0.0
 * @package    TBThemes_Demo_Import
 * @subpackage TBThemes_Demo_Import/includes
 */
class TBThemes_Demo_Import_Deactivator {

	/**
	 * Short Description. (use period)
	 *
	 * Long Description.
	 *
	 * @since    1.0.0
	 */
	public static function deactivate() {
		update_option( '__tbthemes_demo_import_do_redirect', false );

	}

}
