<?php
/**
* Register Go to pro button
*
* @return void
* @since 1.0.4
*
* @package Bizline WordPress theme
*/
function bizline_go_to_pro(){
	Bizline_Customizer::set(array(
		'section' => array(
			'id'       => 'go-to-pro', 
			'type'     => 'anchor',
			'title'    => esc_html__( 'Bizline Pro – Unlock Features', 'bizline' ),
			'url'      => esc_url( 'https://risethemes.com/downloads/bizline-pro/' ),
			'priority' => 0
		)
	));
}
add_action( 'init', 'bizline_go_to_pro' );