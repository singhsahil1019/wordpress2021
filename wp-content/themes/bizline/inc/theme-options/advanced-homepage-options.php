<?php
/**
* Register home page advanced options
*
* @return void
* @since 1.0.1
*
* @package Bizline WordPress theme
*/
function bizline_advanced_homepage_options(){
	Bizline_Customizer::set(array(
		# Front Page option
		'panel' => array(
		    'id'       => 'front-panel'
		),
		# Front Page Option > Advanced
		'section' => array(
		    'id'    => 'home-advanced',
		    'title' => esc_html__( 'Advanced Options','bizline' ),
		),
		'fields' =>array(
			array(
				'id'	=> 'content-on-frontpage',
				'label' => esc_html__( 'Show Content', 'bizline' ),
				'description' => esc_html__( 'Options to show content from page. It will work for sidebar too.', 'bizline' ),
				'default' => true,
				'type'  => 'toggle',
			)
		)
	));
}

add_action( 'init', 'bizline_advanced_homepage_options' );