<?php
/**
* Active callback function of header top bar
*
* @return boolen
* @since 1.0.0
*
* @package Bizline WordPress Theme
*/
if( !function_exists( 'bizline_acb_top_bar' ) ):
	function bizline_acb_top_bar( $control ){
		$value = $control->manager->get_setting( Bizline_Helper::with_prefix( 'show-top-bar' ) )->value();
		return $value;
	}
endif;

/**
* Register Top bar Options
*
* @return void
* @since 1.0.1
*
* @package Bizline WordPress theme
*/
function bizline_topbar_options(){
	Bizline_Customizer::set(array(
		# Theme option
		'panel' => 'panel',
		# Theme Option > Top Bar
		'section' => array(
		    'id'    => 'top-bar',
		    'title' => esc_html__( 'Top Bar', 'bizline' ),
		    'priority'    => 1,
		),
		'fields' => array(
			array(
				'id'	=> 'show-top-bar',
				'label' => esc_html__( 'Enable', 'bizline' ),
				'default' => false,
 				'type'  => 'toggle'
			),
			array(
				'id'	=> 'location',
				'label' => esc_html__( 'Location', 'bizline' ),
				'default' => esc_html( '112 W 34th St, New York' ),
				'type'  => 'text',
				'partial' =>array(
					'selector' => 'span#enhanced-location',
				),
				'active_callback' => 'acb_top_bar'
			),
			array(
				'id'	=> 'phone-num',
				'label' => esc_html__( 'Phone Number', 'bizline' ),
				'default' => esc_html( ' +123455678' ),
				'type'  => 'text',
				'partial' =>array(
					'selector' => 'span#enhanced-phone',
				),
				'active_callback' => 'acb_top_bar'
			),
			array(
				'id'	=> 'email',
				'label' => esc_html__( 'Email', 'bizline' ),
				'default' => esc_html( 'info@yourdomain.com' ),
				'type'  => 'email',
				'partial' =>array(
					'selector' => 'span#enhanced-email',
				),
				'active_callback' => 'acb_top_bar'
			),
			array(
				'id'      => 'header-social-menu',
				'label'   => esc_html__( 'Social Menu Enable', 'bizline' ),
				'description' => esc_html__( 'Please add Social menus for enabling Social menus. Go to Menus for setting up.', 'bizline' ),
				'default' => false,
				'type'    => 'toggle',
				'active_callback' => 'acb_top_bar'
			)
		)
	));
}
add_action( 'init', 'bizline_topbar_options' );