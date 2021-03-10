<?php
/**
* Register home news options
*
* @return void
* @since 1.0.0
*
* @package Bizline WordPress theme
*/
if( !function_exists( 'bizline_acb_front_news' ) ):
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
	function bizline_acb_front_news( $control ){
		$value = $control->manager->get_setting( Bizline_Helper::with_prefix( 'home-news-status' ) )->value();
		return $value;
	}
endif;
function bizline_front_news_options(){
		Bizline_Customizer::set(array(
		    # Front Page option
		    'panel' => array(
		        'id'       => 'front-panel'
		    ),
		    # Front Page Option > News
		    'section' => array(
		        'id'    => 'home-news',
		        'title' => esc_html__( 'News','bizline' ),
		        'priority' => 5
		    ),
		    # Front Page Option > News > settings
		    'fields'  => array(
		    	array(
		    	    'id'	  => 'home-news-status',
		    	    'label'   => esc_html__( 'Enable', 'bizline' ),
		    	    'default' => false,
		    	    'type'    => 'toggle',
		    	),
		    	array(
		    	    'id'	  => 'home-news-title-page',
		    	    'label'   => esc_html__( 'Title', 'bizline' ),
		    	    'description' => esc_html__( 'Select page for section title and description', 'bizline' ),
		    	    'default' => 0,
		    	    'active_callback' => 'acb_front_news',
		    	    'type'    => 'dropdown-pages',
		    	),
    			array(
    			    'id'	  => 'home-news_num_post',
    			    'label'   => esc_html__( 'Number Of Post', 'bizline' ),
    			    'default' => 4,
    			    'active_callback' => 'acb_front_news',
    			    'type'    => 'number',
    			),
    			array(
    			    'id'      => 'home-news-excerpt-length',
    			    'label'   => esc_html__( 'Excerpt Length', 'bizline' ),
    			    'default' => 30,
    			    'active_callback' => 'acb_front_news',
    			    'type'    => 'number',
    			),
		    ),
		));
}
add_action( 'init', 'bizline_front_news_options' );