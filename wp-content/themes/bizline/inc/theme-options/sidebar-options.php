<?php
/**
 * Create options for sidebar.
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */

/**
* Register sidebar Options
*
* @return void
* @since 1.0.0
*
* @package Bizline WordPress theme
*/
function bizline_sidebar_options(){
	Bizline_Customizer::set(array(
		# Theme Options
		'panel'   => 'panel',
		# Theme Options >Sidebar Layout > Settings
		'section' => array(
			'id'     => 'sidebar-options',
			'title'  => esc_html__( 'Sidebar Options','bizline' ),
		),
		'fields' => array(
			# sb - Sidebar
			array(
			    'id'      => 'sidebar-position',
			    'label'   => esc_html__( 'Sidebar Position' , 'bizline' ),
			    'type'    => 'buttonset',
			    'default' => 'no-sidebar',
			    'choices' => array(
			        'left-sidebar'  => esc_html__( 'Left' , 'bizline' ),
			        'right-sidebar' => esc_html__( 'Right' , 'bizline' ),
			        'no-sidebar'    => esc_html__( 'None', 'bizline' ),
			     )
			),
		),
	) );
}
add_action( 'init', 'bizline_sidebar_options' );