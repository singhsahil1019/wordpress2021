<?php
if( !function_exists( 'bizline_acb_custom_header_one' ) ):
	/**
	* Active callback function of header top bar
	*
	* @static
	* @access public
	* @return boolen
	* @since 1.0.0
	*
	* @package Bizline WordPress theme
	*/
	function bizline_acb_custom_header_one( $control ){
		$value = $control->manager->get_setting( Bizline_Helper::with_prefix( 'container-width' ) )->value();
		return 'default' == $value;
	}
endif;

/**
* Register Advanced Options
*
* @return void
* @since 1.0.0
*
* @package Bizline WordPress theme
*/
function bizline_advanced_options(){
	Bizline_Customizer::set(array(
		# Theme option
		'panel' => 'panel',
		# Theme Option > Advanced Options
		'section' => array(
		    'id'    => 'advance-options',
		    'title' => esc_html__( 'Advanced Options', 'bizline' ),
		),
		# Theme Option > Advanced Options > settings
		'fields' => array(
			array(
				'id'	=> 'pre-loader',
				'label' => esc_html__( 'Show Preloader', 'bizline' ),
				'type'  => 'toggle',
			),

			array(
				'id'	=> 'transparent-header',
				'label' => esc_html__( 'Transparent Header', 'bizline' ),
				'type'  => 'toggle',
			),

			array(
			    'id'      => 'assets-version',
			    'label'   => esc_html__( 'Assets Version', 'bizline' ),
			    'type'    => 'buttonset',
			    'default' => 'development',
			    'choices' => array(
			        'development' => esc_html__( 'Development', 'bizline' ),
			        'production'  => esc_html__( 'Production', 'bizline' ),
			    )
			),
			array(
			    'id'      =>  'container-width',
			    'label'   => esc_html__( 'Site Layout', 'bizline' ),
			    'type'    => 'buttonset',
			    'default' => 'default',
			    'choices' => array(
			        'default' => esc_html__( 'Default', 'bizline' ),
			        'box'	  => esc_html__( 'Boxed', 'bizline' ),
			    )
			),
		    array(
		        'id'          	  => 'container-custom-width',
		        'label'   	  	  => esc_html__( 'Container Width', 'bizline' ),
		        'active_callback' => 'acb_custom_header_one',
		        'type'        	  => 'range',
		        'default'     	  => '1140',
	    		'input_attrs' 	  =>  array(
	                'min'   => 400,
	                'max'   => 2000,
	                'step'  => 5,
	            ),
		    ),
		)
	));
}
add_action( 'init', 'bizline_advanced_options' );