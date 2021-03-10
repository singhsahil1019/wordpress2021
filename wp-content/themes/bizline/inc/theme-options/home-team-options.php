<?php
/**
* Register home team options
*
* @return void
* @since 1.0.0
*
* @package Bizline WordPress theme
*/

if( !function_exists( 'bizline_acb_front_team' ) ):
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
	function bizline_acb_front_team( $control ){
		$value = $control->manager->get_setting( Bizline_Helper::with_prefix( 'home-team-status' ) )->value();
		return $value;
	}
endif;

function bizline_front_page_team_options(){
	Bizline_Customizer::set(array(
	    # Front Page option
	    'panel' => array(
	        'id'       => 'front-panel'
	    ),
	    # Front Page Option > Team
	    'section' => array(
	        'id'    => 'home-team',
	        'title' => esc_html__( 'Team','bizline' ),
	        'priority' => 5
	    ),
	    # Front Page Option > Team > settings
	    'fields'  => array(
	    	array(
	    	    'id'	  => 'home-team-status',
	    	    'label'   => esc_html__( 'Enable', 'bizline' ),
	    	    'default' => false,
	    	    'type'    => 'toggle',
	    	),
	    	array(
	    	    'id'      => 'home-team-title-page',
	    	    'label'   => esc_html__( 'Title', 'bizline' ),
	    	    'description' => esc_html__( 'Select page for section title and description', 'bizline' ),
	    	    'default' => 0,
	    	    'active_callback' => 'acb_front_team',
	    	    'type'    => 'dropdown-pages',
	    	),
	    	array(
	    	    'id'      => 'home-team-excerpt-length',
	    	    'label'   => esc_html__( 'Excerpt Length', 'bizline' ),
	    	    'default' => 30,
	    	    'active_callback' => 'acb_front_team',
	    	    'type'    => 'number',
	    	),
	    	array(
	    	  'id'    => 'team-repeater',
	    	  'label' => esc_html__( 'Select Team Fields', 'bizline' ),
	    	  'active_callback' => 'acb_front_team',
	    	  'type'  => 'repeater',
	    	  'limit' => 4,
	    	  'repeat' => array(
	    	    'page' => array(
	    	        'label' => esc_html__( 'Page', 'bizline' ),
	    	    ),
	    	    'text' => array(
	    	        'label' => esc_html__( 'Position', 'bizline' ),
	    	    )
	    	  ),
	    	),
	    ),
	));
}
add_action( 'init', 'bizline_front_page_team_options' );