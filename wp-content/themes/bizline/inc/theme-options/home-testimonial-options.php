<?php
/**
* Register home page testimonial options
*
* @return void
* @since 1.0.0
*
* @package Bizline WordPress theme
*/

if( !function_exists( 'bizline_acb_front_testimonial' ) ):
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
    function bizline_acb_front_testimonial( $control ){
        $value = $control->manager->get_setting( Bizline_Helper::with_prefix( 'home-testimonial-status' ) )->value();
        return $value;
    }
endif;

function bizline_front_page_testimonial_options(){ 
    Bizline_Customizer::set(array(
        # Front Page option
        'panel' => array(
            'id'       => 'front-panel'
        ),
        # Front Page Option > Testimonial
        'section' => array(
            'id'    => 'home-testimonial',
            'title' => esc_html__( 'Testimonial','bizline' ),
            'priority' => 5
        ),
        # Front Page Option > Testimonial > settings
        'fields'  => array(
            array(
                'id'      => 'home-testimonial-status',
                'label'   => esc_html__( 'Enable', 'bizline' ),
                'description' => esc_html__( 'Please select page to display section.', 'bizline' ),
                'default' => false,
                'type'    => 'toggle',
            ),
            array(
                'id'      => 'home-testimonial-image',
                'label'   => esc_html__( 'Background Image', 'bizline' ),
                'active_callback' => 'acb_front_testimonial',
                'type'    => 'image',
            ),
            array(
                'id'      => 'home-testimonial-excerpt-length',
                'label'   => esc_html__( 'Excerpt Length', 'bizline' ),
                'default' => 30,
                'active_callback' => 'acb_front_testimonial',
                'type'    => 'number',
            ),
            array(
              'id'    => 'testimonial-repeater',
              'label' => esc_html__( 'Select Testimonial Fields', 'bizline' ),
              'active_callback' => 'acb_front_testimonial',
              'type'  => 'repeater',
              'limit' => 3,
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
add_action( 'init', 'bizline_front_page_testimonial_options' );