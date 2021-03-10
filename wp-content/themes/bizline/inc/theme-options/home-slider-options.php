<?php
/**
* Register home page slider options
*
* @return void
* @since 1.0.0
*
* @package Bizline WordPress theme
*/

if( !function_exists( 'bizline_acb_front_silder' ) ):
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
	function bizline_acb_front_silder( $control ){
		$value = $control->manager->get_setting( Bizline_Helper::with_prefix( 'home-slider-status' ) )->value();
		return $value;
	}
endif;



function bizline_front_page_slider_options(){ 
    Bizline_Customizer::set(array(
        # Front Page option
        'panel' => array(
            'id'       => 'front-panel',
            'title'    => esc_html__( 'Homepage / Frontpage Options', 'bizline' ),
            'priority' => 5,
        ),
        # Front Page Option > Slider
        'section' => array(
            'id'    => 'home-slider',
            'title' => esc_html__( 'Slider','bizline' ),
            'priority' => 5
        ),
        # Front Page Option > Slider > settings
        'fields'  => array(
        	array(
        	    'id'	  => 'home-slider-status',
        	    'label'   => esc_html__( 'Enable', 'bizline' ),
        	    'default' => false,
        	    'type'    => 'toggle',
        	),
        	array(
        	    'id'	  => 'home-slider-excerpt-length',
        	    'label'   => esc_html__( 'Excerpt Length', 'bizline' ),
        	    'default' => 30,
        	    'active_callback' => 'acb_front_silder',
        	    'type'    => 'number',
        	),
            array(
              'id'    => 'slider-pages',
              'label' => esc_html__( 'Select Pages', 'bizline' ),
              'type'  => 'repeater',
              'active_callback' => 'acb_front_silder',
              'limit' => 3,
              'repeat' => array(
                'page' => array(
                    'label' => '',
                )
              ),
            ),
        	array(
        	    'id'	  => 'home-slider-button-text',
        	    'label'   => esc_html__( 'Button Text', 'bizline' ),
        	    'default' => esc_html__( 'Read More', 'bizline' ),
                'partial' =>array(
                    'selector' => 'span#slider-read-more',
                ),
        	    'active_callback' => 'acb_front_silder',
        	    'type'    => 'text',
        	),
        	array(
        	    'id'	  => 'home-slider-pager',
        	    'label'   => esc_html__( 'Show Pager', 'bizline' ),
        	    'default' => true,
        	    'active_callback' => 'acb_front_silder',
        	    'type'    => 'toggle',
        	),
        	array(
        	    'id'	  => 'home-slider-arrow',
        	    'label'   => esc_html__( 'Show Arrow', 'bizline' ),
        	    'default' => true,
        	    'active_callback' => 'acb_front_silder',
        	    'type'    => 'toggle',
        	),
        ),
    ));
}
add_action( 'init', 'bizline_front_page_slider_options' );