<?php
/**
* Register home call to action options
*
* @return void
* @since 1.0.0
*
* @package Bizline WordPress theme
*/

if( !function_exists( 'bizline_acb_front_cta' ) ):
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
	function bizline_acb_front_cta( $control ){
		$value = $control->manager->get_setting( Bizline_Helper::with_prefix( 'home-cta-status' ) )->value();
		return $value;
	}
endif;

function bizline_front_cta_options(){
		Bizline_Customizer::set(array(
		    # Front Page option
		    'panel' => array(
		        'id'       => 'front-panel'
		    ),
		    # Front Page Option > Call To Action
		    'section' => array(
		        'id'    => 'home-cta',
		        'title' => esc_html__( 'Call To Action','bizline' ),
		        'priority' => 5
		    ),
		    # Front Page Option > Call To Action > settings
		    'fields'  => array(
		    	array(
		    	    'id'	  => 'home-cta-status',
		    	    'label'   => esc_html__( 'Enable', 'bizline' ),
		    	    'default' => false,
		    	    'type'    => 'toggle',
		    	    'description' => esc_html__( 'Also select page to display section.', 'bizline' )
		    	),
	    		array(
	    		    'id'	  => 'home-cta-text',
	    		    'label'   => esc_html__( 'Button Text', 'bizline' ),
	    		    'default' => esc_html__( 'Buy Now', 'bizline' ),
	    	        'partial' =>array(
	    	            'selector' => '.bizline-cat-content .bizline-button-primary',
	    	        ),
	    		    'active_callback' => 'acb_front_cta',
	    		    'type'    => 'text',
	    		),
	    		array(
	    		    'id'      => 'home-cta-excerpt-length',
	    		    'label'   => esc_html__( 'Excerpt Length', 'bizline' ),
	    		    'default' => 30,
	    		    'active_callback' => 'acb_front_cta',
	    		    'type'    => 'number',
	    		),
		    	array(
		    	    'id'	  => 'home-cta-page',
		    	    'label'   => esc_html__( 'Select Page', 'bizline' ),
		    	    'default' => 0,
		    	    'active_callback' => 'acb_front_cta',
		    	    'type'    => 'dropdown-pages',
		    	),
		    ),
		));
}
add_action( 'init', 'bizline_front_cta_options' );