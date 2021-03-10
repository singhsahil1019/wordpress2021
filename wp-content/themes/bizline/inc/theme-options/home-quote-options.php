<?php
if( !function_exists( 'bizline_acb_front_quote' ) ):
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
	function bizline_acb_front_quote( $control ){
		$value = $control->manager->get_setting( Bizline_Helper::with_prefix( 'home-quote-status' ) )->value();
		return $value;
	}
endif;

/**
* Register home page quote options
*
* @return void
* @since 1.0.1
*
* @package Bizline WordPress theme
*/

function bizline_front_page_quote_options(){ 
    Bizline_Customizer::set(array(
    	# Front Page option
    	'panel' => array(
    	    'id' => 'front-panel'
    	),
    	# Front Page Option > Quote
    	'section' => array(
    	    'id'    => 'home-quote',
    	    'title' => esc_html__( 'Quote','bizline' ),
    	    'priority' => 5
    	),
    	# Front Page Option > Quote > settings
    	'fields'  => array(
    		array(
    		    'id'	  => 'home-quote-status',
    		    'label'   => esc_html__( 'Enable', 'bizline' ),
    		    'default' => false,
    		    'type'    => 'toggle'
    		),
    		array(
    		    'id'	  => 'home-quote-title-page',
    		    'label'   => esc_html__( 'Title', 'bizline' ),
    		    'description' => esc_html__( 'This section will get title from the page.', 'bizline' ),
    		    'default' => 0,
    		    'active_callback' => 'acb_front_quote',
    		    'type'    => 'dropdown-pages',
    		),
    		array(
    			'id'	=> 'home-quote-button-text',
    			'label'	=> esc_html__( 'Button Text', 'bizline' ),
    			'default'	=> esc_html__( 'Get a Quote', 'bizline' ),
    			'active_callback' => 'acb_front_quote',
    			'partial' => array(
    				'selector' => '.btn-get-quote'
    			),
    			'type'	=> 'text'
    		),
    		array(
    			'id'	=> 'home-quote-href',
    			'label'	=> esc_html__( 'Link', 'bizline' ),
    			'active_callback' => 'acb_front_quote',
    			'type'	=> 'url'
    		),
    		array(
    			'id' => 'home-quote-margin',
    			'label' => esc_html__( 'Margin (px)', 'bizline' ),
    			'type' => 'dimensions',
    			'active_callback' => 'acb_front_quote',
    			'dimension' => array(
    				'top',
    				'bottom'
    			),
    			'default' => array(
    				'desktop' => array(
    					'top' => 0,
    					'bottom' => 0
    				),
    				'tablet' => array(
    					'top' => 0,
    					'bottom' =>0 
    				),
    				'mobile' => array(
    					'top' => 0,
    					'bottom' => 0
    				)
    			)
    		)
    	)
    ));
}
add_action( 'init', 'bizline_front_page_quote_options' );