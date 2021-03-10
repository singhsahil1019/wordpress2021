<?php

/**
 * Define the internationalization functionality
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @link       as
 * @since      1.0.0
 *
 * @package    TBThemes_Demo_Import
 * @subpackage TBThemes_Demo_Import/includes
 */

/**
 * Define the internationalization functionality.
 *
 * Loads and defines the internationalization files for this plugin
 * so that it is ready for translation.
 *
 * @since      1.0.0
 * @package    TBThemes_Demo_Import
 * @subpackage TBThemes_Demo_Import/includes
 * @author     s <sjunee5@gmail.com>
 */
class TBThemes_Demo_Import_i18n {


	/**
	 * Load the plugin text domain for translation.
	 *
	 * @since    1.0.0
	 */
	public function load_plugin_textdomain() {

		load_plugin_textdomain(
			'tbthemes-demo-import',
			false,
			dirname( dirname( plugin_basename( __FILE__ ) ) ) . '/languages/'
		);

	}



}
