<?php

/**
 * 
 *
 * @link              as
 * @since             1.0.0
 * @package           TBThemes_Demo_Import
 *
 * @wordpress-plugin
 * Plugin Name:       TBThemes Demo Import
 * Plugin URI:        
 * Description:       This is a theme import plugin. Our plugin will help you import the theme content with just a click.
 * Version:           1.0.7
 * Author:            thebootstrapthemes 
 * Author URI:        https://profiles.wordpress.org/thebootstrapthemes/
 * License:           GPL-2.0+
 * License URI:       http://www.gnu.org/licenses/gpl-2.0.txt
 * Text Domain:       tbthemes-demo-import
 * Domain Path:       /languages
 */



// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

/**
 * Currently plugin version.
 * Start at version 1.0.0 and use SemVer - https://semver.org
 * Rename this for your plugin and update it as you release new versions.
 */
define( 'TBTHEMES_DEMO_IMPORT_VERSION', '1.0.7' );



/*Define Constants for this plugin*/
define( 'TBTHEMES_DEMO_IMPORT_PLUGIN_NAME', 'tbthemes-demo-setup' );
define( 'TBTHEMES_DEMO_IMPORT_PATH', plugin_dir_path( __FILE__ ) );
define( 'TBTHEMES_DEMO_IMPORT_URL', plugin_dir_url( __FILE__ ) );
define( 'TBTHEMES_DEMO_IMPORT_TEMPLATE_URL', TBTHEMES_DEMO_IMPORT_URL.'includes/demo-data/' );
define( 'TBTHEMES_DEMO_IMPORT_SCRIPT_PREFIX', ( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ) ? '' : '' );


/**
 * The code that runs during plugin activation.
 * This action is documented in includes/class-tbthemes-demo-import-activator.php
 */
function activate_tbthemes_demo_import() {
	require_once plugin_dir_path( __FILE__ ) . 'includes/class-tbthemes-demo-import-activator.php';
	TBThemes_Demo_Import_Activator::activate();
}

/**
 * The code that runs during plugin deactivation.
 * This action is documented in includes/class-tbthemes-demo-import-deactivator.php
 */
function deactivate_tbthemes_demo_import() {
	require_once plugin_dir_path( __FILE__ ) . 'includes/class-tbthemes-demo-import-deactivator.php';
	TBThemes_Demo_Import_Deactivator::deactivate();
}

register_activation_hook( __FILE__, 'activate_tbthemes_demo_import' );
register_deactivation_hook( __FILE__, 'deactivate_tbthemes_demo_import' );

/**
 * The core plugin class that is used to define internationalization,
 * admin-specific hooks, and public-facing site hooks.
 */
require plugin_dir_path( __FILE__ ) . 'includes/class-tbthemes-demo-import.php';

/**
 * Begins execution of the plugin.
 *
 * Since everything within the plugin is registered via hooks,
 * then kicking off the plugin from this point in the file does
 * not affect the page life cycle.
 *
 * @since    1.0.0
 */

if( !function_exists( 'run_tbthemes_demo_import')){

	function run_tbthemes_demo_import() {
  
	    return TBThemes_Demo_Import::instance();
	}
	run_tbthemes_demo_import()->run();
  }