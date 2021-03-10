<?php
/**
 * Inner banner options in customizer
 *
 * @return void
 * @since 1.0.0
 *
 * @package Bizline WordPress Theme
 */

function bizline_inner_banner_options(){ 
	Bizline_Customizer::set(array(
		# Theme Option > Inner Banner
		'section' => array(
		    'id'       => 'header_image',
		    'priority' => 27,
		    'prefix' => false,
		),
		'fields'  => array(
			array(
				'id'      	  => 'ib-blog-title',
				'label'   	  => esc_html__( 'Title' , 'bizline' ),
				'description' => esc_html__( 'It is displayed when home page is latest posts.' , 'bizline' ),
				'type'	  	  => 'text',
				'priority'    => 10,
			),
		    array(
		        'id'	  	  => 'ib-title-size',
		        'label'   	  => esc_html__( 'Font Size', 'bizline' ),
		        'description' => esc_html__( 'The value is in px. Defaults to 40px.' , 'bizline' ),
		        'default' => array(
		    		'desktop' => 40,
		    		'tablet'  => 32,
		    		'mobile'  => 32,
		    	),
				'input_attrs' =>  array(
		            'min'   => 1,
		            'max'   => 60,
		            'step'  => 1,
		        ),
		        'type' => 'slider',
		        'priority' => 20
		    ),
		    array(
		        'id'      => 'ib-title-color',
		        'label'   => esc_html__( 'Text Color' , 'bizline' ),
		        'type'    => 'color-picker',
		        'default' => '#000000',
		        'priority' => 30
		    ),
		    array(
		    	'id' 	   => 'ib-background-color',
		    	'label'    => esc_html__( 'Overlay Color', 'bizline' ),
		    	'default'  => '',
		    	'type' 	   => 'color-picker',
		    	'priority' => 40,
		    ),
		    array(
		        'id'      => 'ib-text-align',
		        'label'   => esc_html__( 'Alignment' , 'bizline' ),
		        'type'    => 'buttonset',
		        'default' => 'banner-content-center',
		        'choices' => array(
		        	'banner-content-left'   => esc_html__( 'Left' , 'bizline'   ),
		        	'banner-content-center' => esc_html__( 'Center' , 'bizline' ),
		        	'banner-content-right'  => esc_html__( 'Right' , 'bizline'  ),
		         ),
		        'priority' => 50
		    ),
			array(
			    'id'      => 'ib-image-attachment', 
			    'label'   => esc_html__( 'Image Attachment' , 'bizline' ),
			    'type'    => 'buttonset',
			    'default' => 'banner-background-scroll',
			    'choices' => array(
			    	'banner-background-scroll'           => esc_html__( 'Scroll' , 'bizline' ),
			    	'banner-background-attachment-fixed' => esc_html__( 'Fixed' , 'bizline' ),
			    ),
		        'priority' => 60
			),
			array(
			    'id'      	=> 'ib-height',
			    'label'   	=> esc_html__( 'Height (px)', 'bizline' ),
			    'type'    	=> 'slider',
	            'description' => esc_html__( 'The value is in px. Defaults to 420px.' , 'bizline' ),
	            'default' => array(
	        		'desktop' => 180,
	        		'tablet'  => 180,
	        		'mobile'  => 180,
	        	),
	    		'input_attrs' =>  array(
	                'min'   => 1,
	                'max'   => 1000,
	                'step'  => 1,
	            ),
			),
		    'priority' => 70

		),
	) );
}
add_action( 'init', 'bizline_inner_banner_options' );