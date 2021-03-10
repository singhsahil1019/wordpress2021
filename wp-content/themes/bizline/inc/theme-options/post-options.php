<?php
/**
 * Create options for posts.
 *
 * @since 1.0.0
 *
 * @package Bizline WordPress theme
 */

function bizline_post_options(){  
    Bizline_Customizer::set(array(
    	# Theme Options
    	'panel'   => 'panel',
    	# Theme Options > Page Options > Settings
    	'section' => array(
    		'id'    => 'post-options',
    		'title' => esc_html__( 'Post Options','bizline' ),
    	),
    	'fields' => array(
            array(
                'id'      => 'post-category',
                'label'   =>  esc_html__( 'Show Categories', 'bizline' ),
                'default' => 1,
                'type'    => 'toggle',
            ),
            array(
                'id'      => 'post-date',
                'label'   => esc_html__( 'Show Date', 'bizline' ),
                'default' => 1,
                'type'    => 'toggle',
            ),
            array(
                'id'      => 'post-author',
                'label'   =>  esc_html__( 'Show Author', 'bizline' ),
                'default' => 1,
                'type'    => 'toggle',
            ),
            array(
                'id'      => 'excerpt_length',
                'label'   => esc_html__( 'Excerpt Length', 'bizline' ),
                'description' => esc_html__( 'Defaults to 10.', 'bizline' ),
                'default' => 30,
                'type'    => 'number',
            ),
            array(
                'id'      => 'read-more-text',
                'label'   => esc_html__( 'Read More Text', 'bizline' ),
                'default' => esc_html__( 'Read More', 'bizline' ),
                'type'    => 'text'
            )
     	),
    ) );
}
add_action( 'init', 'bizline_post_options' );