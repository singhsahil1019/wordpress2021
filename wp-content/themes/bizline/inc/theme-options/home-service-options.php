<?php
/**
* Register home page service options
*
* @return void
* @since 1.0.0
*
* @package Bizline WordPress theme
*/

if( !function_exists( 'bizline_acb_front_service' ) ):
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
	function bizline_acb_front_service( $control ){
		$value = $control->manager->get_setting( Bizline_Helper::with_prefix( 'home-service-status' ) )->value();
		return $value;
	}
endif;

function bizline_front_page_service_options(){ 
    Bizline_Customizer::set(array(
        # Front Page option
        'panel' => array(
            'id'       => 'front-panel'
        ),
        # Front Page Option > Service
        'section' => array(
            'id'    => 'home-service',
            'title' => esc_html__( 'Services','bizline' ),
            'priority' => 5
        ),
        # Front Page Option > Service > settings
        'fields'  => array(
        	array(
        	    'id'	  => 'home-service-status',
        	    'label'   => esc_html__( 'Enable', 'bizline' ),
        	    'default' => false,
        	    'type'    => 'toggle',
        	),
            array(
                'id'      => 'home-service-title-page',
                'label'   => esc_html__( 'Title', 'bizline' ),
                'description' => esc_html__( 'Select page for section title and description', 'bizline' ),
                'default' => 0,
                'active_callback' => 'acb_front_service',
                'type'    => 'dropdown-pages',
            ),
            array(
                'id'      => 'home-service-excerpt-length',
                'label'   => esc_html__( 'Excerpt Length', 'bizline' ),
                'default' => 30,
                'active_callback' => 'acb_front_service',
                'type'    => 'number',
            ),
    		array(
    		    'id'	  => 'home-service-image',
    		    'label'   => esc_html__( 'Image', 'bizline' ),
    		    'active_callback' => 'acb_front_service',
    		    'type'    => 'image',
    		),
            array(
              'id'    => 'services-pages',
              'label' => esc_html__( 'Select Pages', 'bizline' ),
              'type'  => 'repeater',
              'active_callback' => 'acb_front_service',
              'limit' => 4,
              'repeat' => array(
                'page' => array(
                    'label' => '',
                )
              ),
            ),
        ),
    ));
}
add_action( 'init', 'bizline_front_page_service_options' );