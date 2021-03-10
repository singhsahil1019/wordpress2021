<?php

/**
 * Fired during plugin activation
 *
 * @link       as
 * @since      1.0.0
 *
 * @package    TBThemes_Demo_Import
 * @subpackage TBThemes_Demo_Import/includes
 */

/**
 * Fired during plugin activation.
 *
 * This class defines all code necessary to run during the plugin's activation.
 *
 * @since      1.0.0
 * @package    TBThemes_Demo_Import
 * @subpackage TBThemes_Demo_Import/includes
 * @author     s <sjunee5@gmail.com>
 */
class TBThemes_Demo_Import_Activator {

	/**
	 * Short Description. (use period)
	 *
	 * Long Description.
	 *
	 * @since    1.0.0
	 */
	public static function activate() {
		update_option( '__tbthemes_demo_import_do_redirect', true );
	}

}
